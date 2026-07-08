"""Unified release lineage orchestrator for npm, GitHub, and Sigstore evidence."""

from __future__ import annotations

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from rootkeepers.collectors.npm.main import collect_npm_release


SCHEMA_VERSION = "rootkeepers.release-lineage.v1"


class TrackSkipped(Exception):
    """Raised when a track cannot run because required upstream data is missing."""


def collect_release_lineage_report(
    package_name: str,
    version: str,
    *,
    sigstore_timeout: int = 15,
) -> dict[str, Any]:
    """Run Track A first, then Track B and Track C, and return one JSON document."""
    started_at = _utc_now()
    npm_result = _run_track("npm", lambda: _collect_npm(package_name, version))

    artifact = _artifact_from_npm(npm_result)
    git_head = artifact.get("git_head")
    repo_url = artifact.get("repo_url")
    owner_repo = normalize_github_repository(repo_url)

    downstream_tracks: dict[str, Callable[[], dict[str, Any]]] = {
        "github": lambda: _collect_github(owner_repo, git_head),
        "sigstore": lambda: _collect_sigstore(package_name, version, sigstore_timeout),
    }

    track_results = {"npm": npm_result}
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {
            executor.submit(_run_track, name, collector): name
            for name, collector in downstream_tracks.items()
        }
        for future in as_completed(futures):
            track_results[futures[future]] = future.result()

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "started_at": started_at,
        "package": {
            "ecosystem": "npm",
            "name": package_name,
            "version": version,
        },
        "pipeline": {
            "npm_to_github": {
                "git_head": git_head,
                "repository_url": repo_url,
                "owner_repo": owner_repo,
            }
        },
        "tracks": track_results,
        "summary": _build_summary(track_results),
    }


def normalize_github_repository(repo_url: str | None) -> str | None:
    """Normalize common npm repository URL forms to owner/repo."""
    if not repo_url:
        return None

    cleaned = repo_url.strip()
    cleaned = re.sub(r"^git\+", "", cleaned)
    cleaned = re.sub(r"\.git$", "", cleaned)

    ssh_match = re.match(r"git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+)$", cleaned)
    if ssh_match:
        return f"{ssh_match.group('owner')}/{ssh_match.group('repo')}"

    if cleaned.startswith("github:"):
        return cleaned.removeprefix("github:").strip("/")

    parsed = urlparse(cleaned)
    if parsed.netloc.lower() != "github.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None

    return f"{parts[0]}/{parts[1]}"


def write_json(document: dict[str, Any], output_path: Path | None) -> None:
    rendered = json.dumps(document, indent=2, ensure_ascii=False)
    if output_path is None:
        print(rendered)
        return
    output_path.write_text(rendered + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect a unified npm release lineage report."
    )
    parser.add_argument("package_name", help="npm package name, e.g. vite or @scope/name")
    parser.add_argument("version", help="npm package version, e.g. 5.2.0")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write final JSON to this file instead of stdout",
    )
    parser.add_argument(
        "--sigstore-timeout",
        type=int,
        default=15,
        help="npm attestation request timeout in seconds (default: 15)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    report = collect_release_lineage_report(
        args.package_name,
        args.version,
        sigstore_timeout=args.sigstore_timeout,
    )
    write_json(report, args.output)
    return 0


def _collect_npm(package_name: str, version: str) -> dict[str, Any]:
    result = collect_npm_release(package_name, version)
    if result is None:
        raise RuntimeError("npm collector did not return package data")
    return result


def _collect_github(owner_repo: str | None, git_head: str | None) -> dict[str, Any]:
    if not owner_repo:
        raise TrackSkipped("GitHub repository could not be derived from npm metadata")
    if not git_head:
        raise TrackSkipped("gitHead is missing from npm artifact metadata")
    from rootkeepers.collectors.github.github_collector import collect_github_evidence

    return collect_github_evidence(owner_repo=owner_repo, git_head=git_head)


def _collect_sigstore(
    package_name: str,
    version: str,
    timeout: int,
) -> dict[str, Any]:
    from rootkeepers.collectors.sigstore.main import collect_release_lineage

    return collect_release_lineage(package_name, version, timeout=timeout)


def _run_track(name: str, collector: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return {
            "status": "SUCCESS",
            "data": collector(),
            "error": None,
        }
    except TrackSkipped as error:
        return _track_error("SKIPPED", error)
    except Exception as error:
        if error.__class__.__name__ == "GithubRateLimitError":
            return _track_error(
                "UNVERIFIABLE",
                error,
                reason="GITHUB_RATE_LIMIT_EXCEEDED",
            )
        if name == "sigstore" and error.__class__.__name__ == "CollectorError":
            return _track_error("ERROR", error, reason="SIGSTORE_COLLECT_FAILED")
        return _track_error("ERROR", error, reason=f"{name.upper()}_COLLECT_FAILED")


def _track_error(
    status: str,
    error: Exception,
    *,
    reason: str | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "data": None,
        "error": {
            "type": error.__class__.__name__,
            "reason": reason or error.__class__.__name__.upper(),
            "message": str(error),
        },
    }


def _artifact_from_npm(npm_result: dict[str, Any]) -> dict[str, Any]:
    data = npm_result.get("data")
    if not isinstance(data, dict):
        return {}
    artifact = data.get("artifact")
    return artifact if isinstance(artifact, dict) else {}


def _build_summary(track_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    statuses = {
        track_name: track_result.get("status", "UNKNOWN")
        for track_name, track_result in sorted(track_results.items())
    }
    return {
        "overall_status": "SUCCESS"
        if all(status == "SUCCESS" for status in statuses.values())
        else "PARTIAL",
        "track_statuses": statuses,
    }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


if __name__ == "__main__":
    raise SystemExit(main())
