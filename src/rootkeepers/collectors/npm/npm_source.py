"""Safely download one pinned npm release for optional packJ analysis."""

from __future__ import annotations

import io
import os
import tarfile
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import requests

from rootkeepers.analysis.source_sast import MAX_TARBALL_BYTES, safe_extract_tarball, verify_sri

from .packj import scan_package_source

REGISTRY_URL = "https://registry.npmjs.org"


def scan_npm_package(
    package_name: str,
    version: str,
    *,
    timeout_seconds: int = 30,
) -> dict[str, Any]:
    """Download, integrity-check and statically scan a pinned npm tarball.

    The package is never installed and lifecycle scripts are never executed.
    """
    if os.environ.get("ROOTKEEPERS_ENABLE_PACKJ") != "1":
        return _unavailable("DISABLED")
    if not package_name or not version:
        return _unavailable("PACKAGE_OR_VERSION_MISSING")

    try:
        metadata_response = requests.get(
            f"{REGISTRY_URL}/{quote(package_name, safe='')}/{quote(version, safe='')}",
            timeout=max(1, timeout_seconds),
        )
        metadata_response.raise_for_status()
        metadata = metadata_response.json()
        dist = metadata.get("dist") if isinstance(metadata, dict) else None
        dist = dist if isinstance(dist, dict) else {}
        tarball_url = dist.get("tarball")
        parsed = urlparse(str(tarball_url))
        if parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org":
            return _unavailable("UNTRUSTED_TARBALL_URL")

        response = requests.get(
            tarball_url,
            stream=True,
            timeout=max(1, timeout_seconds),
        )
        response.raise_for_status()
        buffer = io.BytesIO()
        for chunk in response.iter_content(1024 * 1024):
            if not chunk:
                continue
            buffer.write(chunk)
            if buffer.tell() > MAX_TARBALL_BYTES:
                return _unavailable("TARBALL_TOO_LARGE")
        artifact = buffer.getvalue()

        integrity = verify_sri(artifact, dist.get("integrity"))
        if integrity.get("status") == "MISMATCH":
            return {
                "status": "ERROR",
                "reason": "NPM_INTEGRITY_MISMATCH",
                "integrity": integrity,
                "findings": [],
            }
        with tempfile.TemporaryDirectory(prefix="trustgate-packj-") as temporary:
            source_root = safe_extract_tarball(artifact, Path(temporary))
            result = scan_package_source(source_root, timeout_seconds=timeout_seconds)
            result.setdefault("integrity", integrity)
            return result
    except (requests.RequestException, ValueError, OSError, tarfile.TarError) as exc:
        return {**_unavailable("SOURCE_FETCH_FAILED"), "detail": str(exc)}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "UNAVAILABLE", "reason": reason, "findings": []}


__all__ = ["scan_npm_package"]
