from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Callable

try:
    from .cooldown import check_cooldown, REGISTRY, HTTP_TIMEOUT
except ImportError:
    from cooldown import check_cooldown, REGISTRY, HTTP_TIMEOUT

import urllib.error
import urllib.request

MAX_FALLBACK_TRIES = 5

# verify 함수 타입: (패키지명, 버전) -> PASS면 True
VerifyFn = Callable[[str, str], bool]

@dataclass
class GateDecision:
    version: str | None   # 확정 설치 버전. None이면 설치 안 함(차단/보류).
    action: str           # INSTALL / EARLY_APPROVE / FALLBACK / HOLD / BLOCK / NO_CHANGE
    reason: str


# -------------------------------------------------------------
# 레지스트리 헬퍼 (신버전 resolve / 하위 버전 목록 / 기준선)
# -------------------------------------------------------------
def _get_json(url: str) -> dict | None:
    try:
        with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8"))
    except (urllib.error.URLError, ValueError, TimeoutError):
        return None


def get_latest_version(pkg: str) -> str | None:
    meta = _get_json(f"{REGISTRY}/{pkg.replace('/', '%2F')}")
    return meta.get("dist-tags", {}).get("latest") if meta else None


def list_versions(pkg: str) -> list[str]:
    meta = _get_json(f"{REGISTRY}/{pkg.replace('/', '%2F')}")
    return list(meta.get("versions", {}).keys()) if meta else []


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


# ---------------------------------------------------------------------------
# 전체 판정 흐름
# ---------------------------------------------------------------------------
def gate_package(pkg: str, verify: VerifyFn,
                candidate: str | None = None,
                baseline: str | None = None) -> GateDecision:
    """쿨다운 + 계보 검증 흐름으로 확정 설치 버전을 결정"""

    if candidate is None:
        candidate = get_latest_version(pkg)
    if candidate is None:
        return GateDecision(baseline, "BLOCK", f"{pkg}: 신버전 해석 실패")

    if baseline is None:
        baseline = read_baseline(pkg)

    if candidate == baseline:
        return GateDecision(candidate, "NO_CHANGE", f"{pkg}@{candidate}: 변화 없음")

    cd = check_cooldown(pkg, candidate)
    print(f"  [cooldown] {cd.reason}")

    # ===================== Y: 쿨다운 통과 =====================
    if cd.passed:
        if verify(pkg, candidate):                       # 신버전 PASS
            return GateDecision(candidate, "INSTALL",
                                f"{pkg}@{candidate}: 쿨다운 통과 + 계보 PASS")
        # 신버전 FAIL → 구버전 유지 또는 통과하는 하위 버전
        return _fallback(pkg, verify, candidate, baseline)

    # ===================== N: 쿨다운 미경과 ===================
    if baseline is None:
        # 관찰 기간인데 비교할 기준선이 없음 → 조기 승인 불가, 설치 보류
        return GateDecision(None, "HOLD",
                            f"{pkg}@{candidate}: 관찰 기간 + 기준선 없음 → 설치 보류")

    # 1) 구버전 검증 — 기준선이 오염 안 됐나 먼저
    if not verify(pkg, baseline):                        # 구버전 FAIL
        return GateDecision(None, "BLOCK",
                            f"{pkg}: 기준선 {baseline} 오염 → 전체 차단(믿을 기준선 없음)")

    # 2) 신버전 검증 + (diff 대용) 둘 다 PASS면 조기 승인
    if verify(pkg, candidate):                           # 구 PASS + 신 PASS
        return GateDecision(candidate, "EARLY_APPROVE",
                            f"{pkg}@{candidate}: 구·신 둘 다 PASS → 조기 승인")

    # 3) 신버전 FAIL → 구버전 유지, 7일 뒤 재평가
    return GateDecision(baseline, "HOLD",
                        f"{pkg}: 신버전 FAIL → 구버전 {baseline} 유지(7일 뒤 재평가)")


def _fallback(pkg: str, verify: VerifyFn,
              upper: str, baseline: str | None) -> GateDecision:
    """신버전 FAIL 시, 쿨다운 지나고 검증 통과하는 하위 버전으로 하강."""
    tried = 0
    for v in reversed([x for x in list_versions(pkg) if x != upper]):
        if v == baseline:
            return GateDecision(baseline, "FALLBACK",
                                f"{pkg}: 통과 버전 없음 → 구버전 {baseline} 유지")
        if not check_cooldown(pkg, v).passed:
            continue
        if verify(pkg, v):
            return GateDecision(v, "FALLBACK",
                                f"{pkg}: {upper} FAIL → 하위 버전 {v} 선택")
        tried += 1
        if tried >= MAX_FALLBACK_TRIES:
            break
    return GateDecision(baseline, "FALLBACK" if baseline else "BLOCK",
                        f"{pkg}: 통과하는 하위 버전 없음 → "
                        + (f"구버전 {baseline} 유지" if baseline else "설치 차단"))

if __name__ == "__main__":
    # 가짜 계보 검증: 항상 PASS (흐름만 확인)
    def verify(pkg, version):
        return True

    d = gate_package("sigstore", verify, baseline="5.0.0")
    print("action :", d.action)
    print("version:", d.version)
    print("reason :", d.reason)