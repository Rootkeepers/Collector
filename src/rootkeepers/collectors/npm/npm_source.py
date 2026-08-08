"""Download and safely unpack npm source for static analysis only."""

from __future__ import annotations

import io
import tarfile
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

from .packj import scan_package_source

REGISTRY = "https://registry.npmjs.org"


def scan_npm_package(package_name: str, version: str, *, timeout_seconds: int = 30) -> dict[str, Any]:
    """Fetch one pinned npm tarball and pass its inert source tree to packJ."""
    if not _packj_enabled():
        return {"status": "UNAVAILABLE", "reason": "DISABLED", "findings": []}
    try:
        metadata = requests.get(
            f"{REGISTRY}/{quote(package_name, safe='')}/{quote(version, safe='')}", timeout=timeout_seconds
        )
        metadata.raise_for_status()
        tarball_url = metadata.json().get("dist", {}).get("tarball")
        if not isinstance(tarball_url, str) or not tarball_url.startswith("https://"):
            return {"status": "ERROR", "reason": "TARBALL_URL_MISSING", "findings": []}
        tarball = requests.get(tarball_url, timeout=timeout_seconds)
        tarball.raise_for_status()
        with tempfile.TemporaryDirectory(prefix="rootkeepers-packj-") as temporary:
            root = Path(temporary)
            _safe_extract(tarball.content, root)
            # npm tarballs conventionally contain package/, but let packJ scan
            # the actual root for resilient handling of unusual archives.
            source = root / "package"
            return scan_package_source(source if source.is_dir() else root, timeout_seconds=timeout_seconds)
    except (requests.RequestException, ValueError, tarfile.TarError, OSError) as error:
        return {"status": "UNAVAILABLE", "reason": "SOURCE_FETCH_FAILED", "detail": str(error), "findings": []}


def _safe_extract(content: bytes, destination: Path) -> None:
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:gz") as archive:
        root = destination.resolve()
        for member in archive.getmembers():
            target = (destination / member.name).resolve()
            if not target.is_relative_to(root) or member.issym() or member.islnk():
                raise tarfile.TarError(f"unsafe tar member: {member.name}")
        # Members were validated above; extract one by one for Python 3.10
        # compatibility (the ``filter=`` argument arrived later).
        for member in archive.getmembers():
            archive.extract(member, destination)


def _packj_enabled() -> bool:
    import os
    return os.environ.get("ROOTKEEPERS_ENABLE_PACKJ") == "1"
