"""계보 수집 + 6규칙 채점을 한 번에 수행하는 공용 스캔 진입점.

CLI 래퍼(safe-npm)와 웹 콘솔이 **같은 함수**를 쓰게 해서, 같은 패키지에 대해
터미널과 대시보드가 다른 판정을 내놓는 일이 없도록 한다.

(이전에는 CLI가 lineage.evaluate_risk() — 정식 규칙 엔진이 나오기 전의 임시
로직 — 을, 웹 콘솔이 detailed_rule_engine.evaluate_detailed_evidence() 를 각각
쓰고 있었다. 이 모듈이 그 불일치를 없앤다.)
"""

from __future__ import annotations

import os
import sys
import threading
import time
from typing import Any

import rootkeepers.interceptor.lineage as lineage_mod
from rootkeepers.interceptor.baseline import BASELINE_SIZE, build_baseline
from rootkeepers.interceptor.cooldown import CooldownResult, check_cooldown
from rootkeepers.interceptor.detailed_rule_engine import (
    evaluate_detailed_evidence,
    evidence_from_lineage,
)

# 기준선 수집 범위. "npm"은 추가 호출이 0회라 기본으로 켜 둔다.
# "sigstore"는 릴리스당 1회가 더 들고, "off"는 완전히 끈다.
BASELINE_MODE = os.getenv("TRUSTGATE_BASELINE", "sigstore").strip().lower()


def _collect_baseline(package_name: str, resolved_version: str | None) -> dict | None:
    """과거 릴리스로 기준선을 만든다. 실패해도 스캔을 막지 않는다.

    기준선이 없으면 규칙이 UNVERIFIABLE로 남을 뿐이므로, 여기서 나는 오류가
    설치 판정 자체를 중단시켜서는 안 된다.
    """
    if BASELINE_MODE == "off" or not resolved_version:
        return None
    try:
        from rootkeepers.collectors.npm.crawler import fetch_package_data
        package_doc = fetch_package_data(package_name)
        if not package_doc:
            return None

        collect_sigstore = None
        if BASELINE_MODE in ("sigstore", "full"):
            from rootkeepers.collectors.sigstore.__main__ import collect_release_lineage
            collect_sigstore = collect_release_lineage

        return build_baseline(package_doc, package_name, resolved_version,
                              limit=BASELINE_SIZE, collect_sigstore=collect_sigstore)
    except Exception as exc:  # noqa: BLE001 — best-effort
        sys.stderr.write(f"[baseline] {package_name} 기준선 수집 실패 (무시하고 진행): {exc}\n")
        return None


def _merge_baseline(existing: Any, collected: dict[str, Any]) -> dict[str, Any]:
    """수집한 기준선을 report의 기존 기준선 **위에 얹는다** (덮어쓰지 않는다).

    lineage의 GitHub 트랙은 이미 최근 태그를 기준으로 릴리스별
    ``commit``(PR·리뷰어 포함)·``tags``·``workflow_entry_points``를 수집해 둔다.
    예전에는 ``report["baseline"]``을 통째로 교체해서 그 데이터를 버렸고, 그
    결과 API 비용은 이미 지불했는데도 orphan_release·unreviewed가 근거 부족
    (UNVERIFIABLE)으로 남았다.

    두 릴리스 목록은 키가 서로 달라(sigstore 쪽은 npm version, GitHub 쪽은 git
    태그) 항목 단위로 합치지 않고 이어 붙인다. 규칙 엔진의 소비부가 자기에게
    필요한 필드를 가진 항목만 골라 쓰기 때문에 — 예를 들어 PR 기준선은
    ``commit.pull_requests``가 있는 항목만, 워크플로 기준선은
    ``workflow_entry_points``가 있는 항목만 본다 — 이어 붙여도 서로를 오염시키지
    않는다. 겹치는 릴리스가 있으면 워크플로 경로가 중복될 수 있으나, 소비부가
    집합 포함 여부만 보므로 판정에는 영향이 없다.

    한계: GitHub 트랙의 태그 기준선은 "저장소의 최근 태그 5개"라서, 아주 오래된
    버전을 스캔하면 그 시절이 아닌 현재 시점의 거버넌스와 비교하게 된다.
    """
    merged = dict(collected)
    existing_github = existing.get("github") if isinstance(existing, dict) else None
    if not isinstance(existing_github, dict):
        return merged
    existing_releases = existing_github.get("releases")
    if not isinstance(existing_releases, list) or not existing_releases:
        return merged

    collected_github = merged.get("github")
    collected_github = collected_github if isinstance(collected_github, dict) else {}
    collected_releases = collected_github.get("releases")
    collected_releases = collected_releases if isinstance(collected_releases, list) else []

    merged_github = {
        **existing_github,
        **collected_github,
        "releases": [*existing_releases, *collected_releases],
    }
    if collected_releases:
        # 어느 쪽에서 온 기준선인지 감사 로그에서 구분할 수 있게 남긴다.
        merged_github["source"] = f"{existing_github.get('source') or 'github'}+sigstore_provenance"
    merged["github"] = merged_github
    return merged

# ---------------------------------------------------------------------------
# 트랙별 실측 소요시간 계측 — lineage._run_track을 감싼다 (원본 코드는 수정하지 않음).
# 스캔은 _scan_lock으로 직렬화되므로 전역 dict를 그대로 써도 안전하다.
# ---------------------------------------------------------------------------
_scan_lock = threading.Lock()
_current_timings: dict[str, int] = {}

# 이 모듈이 두 번 로드되면(reload, 또는 sys.path 차이로 같은 파일이 다른 이름으로
# import되면) 패치가 패치를 감싸 무한 재귀에 빠진다. 원본을 lineage 모듈에
# 보관해 두고 항상 그것을 기준으로 감싼다.
_original_run_track = getattr(lineage_mod, "_trustgate_original_run_track", lineage_mod._run_track)
lineage_mod._trustgate_original_run_track = _original_run_track


def _timed_run_track(name, collector):
    start = time.perf_counter()
    result = _original_run_track(name, collector)
    _current_timings[name] = round((time.perf_counter() - start) * 1000)
    return result


lineage_mod._run_track = _timed_run_track


def scan_package(package_name: str, version: str | None = None) -> dict[str, Any]:
    """패키지 하나를 실제로 수집·채점하고 표준 결과 dict를 돌려준다.

    Args:
        package_name: npm 패키지명.
        version: 검사할 버전. None이면 npm 트랙이 latest로 resolve한다.

    Returns:
        verdict/score/rules/evidence/timing/cooldown 등을 담은 dict.
        ``raw_report``에는 원본 계보 보고서가 그대로 들어 있어, 호출자가
        추가 가공(예: 대시보드의 파이프라인 노드)을 할 수 있다.
    """
    with _scan_lock:
        _current_timings.clear()
        t_start = time.perf_counter()
        report = lineage_mod.collect_release_lineage_report(package_name, version)
        total_ms = round((time.perf_counter() - t_start) * 1000)
        timing = dict(_current_timings)

    resolved_version = report.get("package", {}).get("version") or version
    if resolved_version:
        cooldown = check_cooldown(package_name, resolved_version)
    else:
        cooldown = CooldownResult(False, None, None, None, "버전을 확인할 수 없어 쿨다운을 판정하지 못했습니다.")

    # 과거 릴리스 기준선을 report에 붙인다 — evidence_from_lineage()가
    # report["baseline"]에서 읽어 가도록 이미 설계되어 있다. GitHub 트랙이 이미
    # 수집해 둔 기준선을 버리지 않도록 교체가 아니라 병합한다(_merge_baseline).
    baseline = _collect_baseline(package_name, resolved_version)
    if baseline:
        report["baseline"] = _merge_baseline(report.get("baseline"), baseline)

    evidence = evidence_from_lineage(report)
    decision = evaluate_detailed_evidence(evidence)

    return {
        "ok": True,
        "package": report.get("package", {"name": package_name, "version": version}),
        "verdict": decision["verdict"],
        "score": decision["score"],
        "threshold": decision["threshold"],
        "reason": decision["reason"],
        "corroboration": decision["corroboration"],
        "rules": decision["rules"],
        "evidence": evidence,
        "track_statuses": report.get("summary", {}).get("track_statuses", {}),
        "cooldown": {
            "passed": cooldown.passed,
            "published": cooldown.published.isoformat() if cooldown.published else None,
            "age_days": round(cooldown.age_days, 2) if cooldown.age_days is not None else None,
            "remain_days": round(cooldown.remain_days, 2) if cooldown.remain_days is not None else None,
            "reason": cooldown.reason,
        },
        "timing": {
            "npm": timing.get("npm", 0),
            "github": timing.get("github", 0),
            "sigstore": timing.get("sigstore", 0),
            "total": total_ms,
        },
        "generated_at": report.get("generated_at"),
        "raw_report": report,
    }


__all__ = ["scan_package"]
