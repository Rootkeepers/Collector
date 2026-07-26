"""npm/GitHub/Sigstore 증거를 하나로 합치는 통합 릴리스 계보 오케스트레이터."""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import urlparse

from rootkeepers.collectors.npm._main_ import collect_npm_release


SCHEMA_VERSION = "rootkeepers.release-lineage.v1"


class TrackSkipped(Exception):
    """필요한 상위 데이터가 없어 트랙 실행 자체를 건너뛸 때 발생시키는 예외."""


def collect_release_lineage_report(
    package_name: str,
    version: str | None,
    *,
    sigstore_timeout: int = 15,
) -> dict[str, Any]:
    """Track A를 먼저 실행한 뒤 Track B, Track C를 실행해 JSON 문서 하나로 합친다.

    Args:
        package_name: npm 패키지명 (예: "lodash", "@scope/name").
        version: 검사할 버전. None이면 버전 미지정 설치로 간주하고, 이 경우
            npm 트랙이 "latest" dist-tag로 resolve한 뒤 그 resolve된 버전을
            GitHub/Sigstore 트랙에도 그대로 전달한다.
        sigstore_timeout: npm attestation 요청 타임아웃(초).
    """
    started_at = _utc_now()
    npm_result = _run_track("npm", lambda: _collect_npm(package_name, version))

    artifact = _artifact_from_npm(npm_result)
    npm_git_head = artifact.get("git_head")
    npm_repo_url = artifact.get("repo_url")
    npm_owner_repo = normalize_github_repository(npm_repo_url)

    # npm 트랙이 version=None을 latest로 resolve했을 수 있으므로, downstream
    # 트랙(특히 Sigstore attestation URL 조립)에는 원본 version이 아니라
    # 실제로 resolve된 버전을 전달해야 한다. 그렇지 않으면 version=None인
    # "bare install" 케이스에서 Sigstore 요청 URL에 "None"이 그대로 박힌다.
    resolved_version = _resolved_version_from_npm(npm_result, fallback=version)

    track_results = {"npm": npm_result}
    github_git_head = npm_git_head
    github_owner_repo = npm_owner_repo
    commit_source = "npm.artifact.gitHead" if npm_git_head else None
    repository_source = "npm.artifact.repository" if npm_owner_repo else None

    if npm_git_head:
        # The normal path has all of Track B's inputs.  Keep GitHub and
        # Sigstore concurrent to avoid adding latency to ordinary packages.
        downstream_tracks: dict[str, Callable[[], dict[str, Any]]] = {
            "github": lambda: _collect_github(github_owner_repo, github_git_head),
            "sigstore": lambda: _collect_sigstore(
                package_name, resolved_version, sigstore_timeout
            ),
        }
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                executor.submit(_run_track, name, collector): name
                for name, collector in downstream_tracks.items()
            }
            for future in as_completed(futures):
                track_results[futures[future]] = future.result()
    else:
        # npm's dist.gitHead is optional and is frequently absent for
        # monorepo/automated releases.  In that case Track C's signed SLSA
        # provenance is the stronger source of the build commit.  Track B
        # must wait for it instead of being skipped in parallel.
        sigstore_result = _run_track(
            "sigstore",
            lambda: _collect_sigstore(package_name, resolved_version, sigstore_timeout),
        )
        track_results["sigstore"] = sigstore_result
        slsa_repository, slsa_commit = _slsa_git_reference(sigstore_result)
        if slsa_commit:
            github_git_head = slsa_commit
            commit_source = "sigstore.slsa_predicate.commit"
        if slsa_repository:
            github_owner_repo = normalize_github_repository(slsa_repository)
            repository_source = "sigstore.slsa_predicate.repository"
        track_results["github"] = _run_track(
            "github", lambda: _collect_github(github_owner_repo, github_git_head)
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _utc_now(),
        "started_at": started_at,
        "package": {
            "ecosystem": "npm",
            "name": package_name,
            "version": resolved_version,
        },
        "pipeline": {
            "npm_to_github": {
                "git_head": npm_git_head,
                "repository_url": npm_repo_url,
                "owner_repo": npm_owner_repo,
                "github_lookup": {
                    "git_head": github_git_head,
                    "owner_repo": github_owner_repo,
                    "commit_source": commit_source,
                    "repository_source": repository_source,
                },
            }
        },
        "tracks": track_results,
        "summary": _build_summary(track_results),
    }


def evaluate_risk(report: dict[str, Any]) -> dict[str, Any]:
    """계보 리포트를 기반으로 한 임시 PASS/RISK/UNVERIFIABLE 판정.

    참고: 이 함수는 아직 없는 정식 탐지 규칙 엔진(Orphan Release, Unreviewed,
    Workflow Drift, OIDC Mismatch, Unexpected Builder, Tag/Identity Drift —
    5.1~5.6 항목)과 0~100 신뢰 점수 모델(5.7)이 완성되기 전까지 쓰는 임시
    대체 로직이다. 지금은 (a) 각 트랙이 성공했는지와 (b) Track C 내부에서
    이미 계산된 Sigstore OIDC-mismatch 교차 검증이 통과했는지만 확인한다.
    규칙 엔진이 준비되면 이 함수는 통째로 교체되어야 한다.

    Args:
        report: ``collect_release_lineage_report``의 반환값.

    Returns:
        ``verdict``("PASS" | "RISK" | "UNVERIFIABLE"), 잠정 ``score``
        (0~100), 사람이 읽을 수 있는 ``reason``을 담은 dict.
    """
    track_statuses = report.get("summary", {}).get("track_statuses", {})
    tracks = report.get("tracks", {})

    if track_statuses.get("npm") != "SUCCESS":
        return _risk_verdict(
            "UNVERIFIABLE",
            0,
            "npm 메타데이터 수집에 실패해 계보 확인을 시작할 수 없음",
        )

    if track_statuses.get("sigstore") == "SUCCESS":
        sigstore_data = tracks.get("sigstore", {}).get("data") or {}
        validation = sigstore_data.get("validation", {})
        if validation.get("status") == "FAIL" or validation.get("passed") is False:
            mismatches = []
            for rule in validation.get("rules", []):
                mismatches.extend(rule.get("mismatches", []))
            reason = "; ".join(
                m.get("message", "") for m in mismatches if m.get("message")
            ) or "Sigstore OIDC/서명 신원이 빌드 출처와 일치하지 않음"
            return _risk_verdict("RISK", 10, reason)

    incomplete_tracks = [
        name for name, status in track_statuses.items() if status != "SUCCESS"
    ]
    if incomplete_tracks:
        return _risk_verdict(
            "UNVERIFIABLE",
            50,
            f"일부 계보 트랙을 확인할 수 없음: {', '.join(sorted(incomplete_tracks))}",
        )

    return _risk_verdict("PASS", 90, "npm/GitHub/Sigstore 계보 확인 완료, 이상 없음")


def _risk_verdict(verdict: str, score: int, reason: str) -> dict[str, Any]:
    return {"verdict": verdict, "score": score, "reason": reason}


def normalize_github_repository(repo_url: str | None) -> str | None:
    """npm에서 흔히 쓰이는 repository URL 형태를 owner/repo로 정규화한다."""
    if not repo_url:
        return None

    cleaned = repo_url.strip()
    cleaned = re.sub(r"^git\+", "", cleaned)
    # npm repository.url에 ``#main``/``#master`` 같은 브랜치 fragment가 붙는
    # 경우가 있다 (예: ``git+https://github.com/owner/repo.git#main``).
    # ``.git`` 제거보다 먼저 잘라내지 않으면 문자열 끝이 ``.git``이 아니게
    # 되어 뒤의 ``.git$`` 정규식이 매칭되지 않고, owner_repo에 ``.git``이
    # 그대로 남아 존재하지 않는 저장소로 조회하게 된다.
    cleaned = re.sub(r"[#?].*$", "", cleaned)
    cleaned = re.sub(r"\.git$", "", cleaned)

    ssh_match = re.match(r"git@github\.com:(?P<owner>[^/]+)/(?P<repo>[^/]+)$", cleaned)
    if ssh_match:
        return f"{ssh_match.group('owner')}/{ssh_match.group('repo')}"

    if cleaned.startswith("github:"):
        return cleaned.removeprefix("github:").strip("/")

    parsed = urlparse(cleaned)
    # ``git+ssh://git@github.com/owner/repo.git`` is a common npm repository
    # form.  ``netloc`` includes the username in that case, while ``hostname``
    # remains github.com.
    if (parsed.hostname or "").lower() != "github.com":
        return None

    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None

    return f"{parts[0]}/{parts[1]}"


def _collect_npm(package_name: str, version: str) -> dict[str, Any]:
    result = collect_npm_release(package_name, version)
    if result is None:
        raise RuntimeError("npm 수집기가 패키지 데이터를 반환하지 않았습니다")
    return result


def _collect_github(owner_repo: str | None, git_head: str | None) -> dict[str, Any]:
    if not owner_repo:
        raise TrackSkipped("npm 메타데이터에서 GitHub 저장소를 알아낼 수 없습니다")
    if not git_head:
        raise TrackSkipped("npm artifact 메타데이터에 gitHead가 없습니다")
    from rootkeepers.collectors.github.github_collector import collect_github_evidence

    return collect_github_evidence(owner_repo=owner_repo, git_head=git_head)


def _collect_sigstore(
    package_name: str,
    version: str,
    timeout: int,
) -> dict[str, Any]:
    from rootkeepers.collectors.sigstore._main_ import collect_release_lineage

    return collect_release_lineage(package_name, version, timeout=timeout)


def _slsa_git_reference(sigstore_track: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return repository and commit carried by a successful SLSA result.

    The Sigstore collector normalizes the relevant predicate fields under
    ``slsa_predicate``.  This helper intentionally treats malformed or failed
    Track C results as missing evidence, so the GitHub track remains
    ``SKIPPED`` rather than guessing a commit.
    """
    if sigstore_track.get("status") != "SUCCESS":
        return None, None
    data = sigstore_track.get("data")
    if not isinstance(data, dict):
        return None, None
    predicate = data.get("slsa_predicate")
    if not isinstance(predicate, dict):
        return None, None
    repository = predicate.get("repository")
    commit = predicate.get("commit")
    return (
        repository if isinstance(repository, str) and repository else None,
        commit if isinstance(commit, str) and commit else None,
    )


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


def _resolved_version_from_npm(npm_result: dict[str, Any], *, fallback: str | None) -> str | None:
    """npm 트랙이 실제로 resolve한 버전을 다시 꺼내온다.

    ``version``이 생략되면(버전 미지정 ``npm install <package>``), npm
    트랙이 내부적으로 "latest" dist-tag로 resolve한다. downstream
    트랙들은 원본 ``None``/생략값이 아니라 그 resolve된 버전을 써야
    하며, 그렇지 않으면 Sigstore attestation URL 조립이 깨진다.
    """
    data = npm_result.get("data")
    if not isinstance(data, dict):
        return fallback

    package = data.get("package")
    if not isinstance(package, dict):
        return fallback

    resolved = package.get("version")
    return resolved if isinstance(resolved, str) and resolved else fallback


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
