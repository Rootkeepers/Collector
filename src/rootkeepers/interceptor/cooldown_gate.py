"""package-lock.json에서 패키지의 현재 설치 버전(기준선)을 읽는다."""

from __future__ import annotations

import json
import os


def read_baseline(pkg: str, lockfile: str = "package-lock.json") -> str | None:
    if not os.path.exists(lockfile):
        return None
    try:
        with open(lockfile, encoding="utf-8") as f:
            data = json.load(f)
    except (ValueError, OSError):
        return None
    node = data.get("packages", {}).get(f"node_modules/{pkg}")
    return node["version"] if node and "version" in node else None