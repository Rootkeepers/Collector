"""신버전이 배포된 지 N일 지났는지만 판정."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone

REGISTRY = "https://registry.npmjs.org"
HTTP_TIMEOUT = 10
COOLDOWN_DAYS = 7

def get_publish_date(pkg: str, version: str) -> datetime | None:
    """신버전의 배포일(레지스트리 게시 시각, UTC)을 가져온다. 없으면 None."""
    pkg_path = pkg.replace("/", "%2F")
    try:
        with urllib.request.urlopen(f"{REGISTRY}/{pkg_path}", timeout=HTTP_TIMEOUT) as resp:
            meta = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError, TimeoutError):
        return None
    
    ts = meta.get("time", {}).get(version)
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None

def check_cooldown(pkg: str, version: str,
                cooldown_days: int = COOLDOWN_DAYS) -> tuple[bool, str]:
    """신버전 배포일로부터 N일 경과? 판정
    배포일을 알 수 없으면 보수적으로 미경과(False)로 처리"""
    published = get_publish_date(pkg, version)

    if published is None:
        return False, f"{pkg}@{version}: 배포일 불명 → 미경과 처리(보수적)"

    age = (datetime.now(timezone.utc) - published).total_seconds() / 86400.0
    date_str = published.strftime("%Y-%m-%d %H:%M UTC")

    if age >= cooldown_days:
        return True, f"{pkg}@{version}: {date_str} 배포, {age:.1f}일 경과 → 쿨다운 통과"

    remain = cooldown_days - age
    return False, (f"{pkg}@{version}: {date_str} 배포, {age:.1f}일 경과 "
                    f"(<{cooldown_days}일), {remain:.1f}일 대기")