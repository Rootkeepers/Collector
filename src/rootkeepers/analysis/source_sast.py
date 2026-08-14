"""Safe npm artifact extraction and optional Semgrep analysis.

Downloaded package code is never installed or executed.  Semgrep receives only an
inert temporary source directory and its JSON output is normalized before use.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sysconfig
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, urlparse

import requests

from rootkeepers.paths import PROJECT_ROOT

REGISTRY_URL = "https://registry.npmjs.org"
RULES_PATH = Path(__file__).resolve().parent / "rules" / "npm-supply-chain.yml"
MAX_TARBALL_BYTES = int(os.getenv("TRUSTGATE_SAST_MAX_TARBALL_MB", "25")) * 1024 * 1024
MAX_EXTRACTED_BYTES = int(os.getenv("TRUSTGATE_SAST_MAX_EXTRACTED_MB", "120")) * 1024 * 1024
MAX_FILES = 20_000
DOWNLOAD_TIMEOUT = float(os.getenv("TRUSTGATE_SAST_DOWNLOAD_TIMEOUT_SECONDS", "30"))
SEMGREP_TIMEOUT = int(os.getenv("TRUSTGATE_SEMGREP_TIMEOUT_SECONDS", "90"))


class UnsafeArchiveError(ValueError):
    """Raised when an npm archive attempts to escape its inert extraction root."""


def _safe_member_path(root: Path, member_name: str) -> Path:
    posix = PurePosixPath(member_name)
    if posix.is_absolute() or ".." in posix.parts:
        raise UnsafeArchiveError(f"unsafe archive member: {member_name}")
    destination = (root / Path(*posix.parts)).resolve()
    if destination != root and root not in destination.parents:
        raise UnsafeArchiveError(f"archive path escaped root: {member_name}")
    return destination


def safe_extract_tarball(data: bytes, destination: Path) -> Path:
    """Extract regular files/directories only, enforcing count and size limits."""
    root = destination.resolve()
    root.mkdir(parents=True, exist_ok=True)
    total = 0
    count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for member in archive:
            count += 1
            if count > MAX_FILES:
                raise UnsafeArchiveError("archive contains too many members")
            target = _safe_member_path(root, member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise UnsafeArchiveError(f"links/devices are not allowed: {member.name}")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            total += member.size
            if total > MAX_EXTRACTED_BYTES:
                raise UnsafeArchiveError("archive expands beyond configured size limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                continue
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)
    package_root = root / "package"
    return package_root if package_root.is_dir() else root


def verify_sri(data: bytes, integrity: str | None) -> dict[str, Any]:
    if not integrity:
        return {"status": "UNVERIFIED", "reason": "NPM_INTEGRITY_MISSING"}
    for token in integrity.split():
        algorithm, separator, expected = token.partition("-")
        if not separator or algorithm not in hashlib.algorithms_available:
            continue
        actual = base64.b64encode(hashlib.new(algorithm, data).digest()).decode("ascii")
        if actual == expected:
            return {"status": "VERIFIED", "algorithm": algorithm}
    return {"status": "MISMATCH", "reason": "NPM_INTEGRITY_MISMATCH"}


def _download_artifact(package_name: str, version: str) -> tuple[bytes, dict[str, Any]]:
    metadata_url = f"{REGISTRY_URL}/{quote(package_name, safe='')}/{quote(version, safe='')}"
    metadata_response = requests.get(metadata_url, timeout=DOWNLOAD_TIMEOUT)
    metadata_response.raise_for_status()
    metadata = metadata_response.json()
    dist = metadata.get("dist") or {}
    tarball_url = dist.get("tarball")
    parsed = urlparse(str(tarball_url))
    if parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org":
        raise ValueError("npm tarball URL is outside registry.npmjs.org")
    response = requests.get(tarball_url, stream=True, timeout=DOWNLOAD_TIMEOUT)
    response.raise_for_status()
    buffer = io.BytesIO()
    for chunk in response.iter_content(1024 * 1024):
        if not chunk:
            continue
        buffer.write(chunk)
        if buffer.tell() > MAX_TARBALL_BYTES:
            raise ValueError("npm tarball exceeds configured size limit")
    return buffer.getvalue(), metadata


def _manifest_findings(source_root: Path) -> list[dict[str, Any]]:
    manifest = source_root / "package.json"
    if not manifest.is_file():
        return []
    try:
        payload = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError, UnicodeError):
        return []
    findings = []
    for name in ("preinstall", "install", "postinstall"):
        command = (payload.get("scripts") or {}).get(name)
        if command:
            findings.append({
                "rule_id": f"manifest.lifecycle.{name}", "severity": "WARNING",
                "path": "package.json", "line": None,
                "message": f"npm {name} lifecycle script is present",
                "evidence": str(command)[:300],
            })
    return findings


def _semgrep_command() -> list[str] | None:
    configured = os.getenv("TRUSTGATE_SEMGREP_COMMAND", "semgrep").strip()
    if not configured:
        return None
    command = shlex.split(configured, posix=os.name != "nt")
    if not command:
        return None
    if shutil.which(command[0]):
        return command
    # Windows Python installs commonly place console scripts outside PATH.  The
    # optional dependency is still usable from the interpreter's scripts dir.
    if configured == "semgrep":
        executable = Path(sysconfig.get_path("scripts")) / (
            "semgrep.exe" if os.name == "nt" else "semgrep"
        )
        if executable.is_file():
            return [str(executable)]
    return None


def semgrep_available() -> bool:
    """Return whether the configured Semgrep executable can be launched."""
    return _semgrep_command() is not None


def _normalize_semgrep(payload: dict[str, Any], source_root: Path) -> list[dict[str, Any]]:
    findings = []
    for result in (payload.get("results") or [])[:200]:
        extra = result.get("extra") or {}
        path = Path(result.get("path") or "")
        try:
            relative = str(path.resolve().relative_to(source_root.resolve()))
        except (OSError, ValueError):
            relative = path.name
        findings.append({
            "rule_id": result.get("check_id"),
            "severity": str(extra.get("severity") or "INFO").upper(),
            "path": relative.replace("\\", "/"),
            "line": (result.get("start") or {}).get("line"),
            "message": extra.get("message") or "Semgrep finding",
        })
    return findings


def run_semgrep(source_root: Path) -> dict[str, Any]:
    command = _semgrep_command()
    if command is None:
        return {
            "status": "UNAVAILABLE", "reason": "SEMGREP_NOT_INSTALLED",
            "findings": [], "finding_count": 0,
        }
    try:
        completed = subprocess.run(
            [*command, "scan", "--config", str(RULES_PATH), "--json", "--metrics", "off",
             "--no-git-ignore", str(source_root)],
            cwd=str(PROJECT_ROOT), capture_output=True, text=True,
            timeout=SEMGREP_TIMEOUT, check=False,
        )
        payload = json.loads(completed.stdout or "{}")
        findings = _normalize_semgrep(payload, source_root)
        errors = payload.get("errors") or []
        if completed.returncode not in (0, 1) and not findings:
            return {
                "status": "ERROR", "reason": "SEMGREP_EXIT_NONZERO",
                "exit_code": completed.returncode, "stderr": completed.stderr[-1000:],
                "findings": [], "finding_count": 0,
            }
        return {
            "status": "FINDINGS" if findings else "CLEAN",
            "engine": "semgrep", "exit_code": completed.returncode,
            "findings": findings, "finding_count": len(findings),
            "errors": errors[:10],
        }
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "reason": "SEMGREP_TIMEOUT", "findings": [], "finding_count": 0}
    except Exception as exc:  # noqa: BLE001 - optional tool isolation
        return {
            "status": "ERROR", "reason": f"{exc.__class__.__name__}: {exc}",
            "findings": [], "finding_count": 0,
        }


def analyze_package_source(package_name: str, version: str | None) -> dict[str, Any]:
    """Download, verify, extract and scan one pinned npm artifact without execution."""
    if not package_name or not version:
        return {
            "status": "UNAVAILABLE", "reason": "PACKAGE_OR_VERSION_MISSING",
            "findings": [], "finding_count": 0,
        }
    try:
        data, metadata = _download_artifact(package_name, version)
        integrity = verify_sri(data, (metadata.get("dist") or {}).get("integrity"))
        if integrity["status"] == "MISMATCH":
            return {
                "status": "ERROR", "reason": "NPM_INTEGRITY_MISMATCH",
                "integrity": integrity, "findings": [], "finding_count": 0,
            }
        with tempfile.TemporaryDirectory(prefix="trustgate-sast-") as temporary:
            source_root = safe_extract_tarball(data, Path(temporary))
            manifest = _manifest_findings(source_root)
            semgrep = run_semgrep(source_root)
            findings = [*manifest, *(semgrep.get("findings") or [])]
            return {
                "status": "FINDINGS" if findings else (
                    "PARTIAL" if semgrep.get("status") in {"UNAVAILABLE", "ERROR"} else "CLEAN"
                ),
                "artifact": {"bytes": len(data), "integrity": integrity},
                "semgrep": {key: value for key, value in semgrep.items() if key != "findings"},
                "findings": findings[:200], "finding_count": len(findings),
                "advisory_only": True,
            }
    except Exception as exc:  # noqa: BLE001 - optional analysis must not affect install gate
        return {
            "status": "ERROR", "reason": f"{exc.__class__.__name__}: {exc}",
            "findings": [], "finding_count": 0, "advisory_only": True,
        }


__all__ = [
    "analyze_package_source", "run_semgrep", "semgrep_available",
    "safe_extract_tarball", "verify_sri", "UnsafeArchiveError",
]
