"""Historical scan comparison and installed-dependency vulnerability monitoring."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any

from rootkeepers.analysis.vulnerability import query_vulnerabilities, query_vulnerability_ids
from rootkeepers.interceptor.inventory import collect_inventory

_VERDICT_ORDER = {"PASS": 0, "UNVERIFIABLE": 1, "UNVERIFIABLE (RISK)": 2, "RISK": 2}


def _active_rule_ids(rules: list[dict[str, Any]] | None) -> set[str]:
    return {
        str(rule.get("id")) for rule in (rules or [])
        if rule.get("band") in {"WARN", "RISK"} or rule.get("state") == "MATCH"
    }


def compare_scan_history(scan: dict[str, Any], history: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare the current authoritative decision with the last distinct observation."""
    package = scan.get("package") or {}
    name = package.get("name")
    current_version = package.get("version")
    current_verdict = scan.get("verdict")
    current_score = int(scan.get("score") or 0)

    candidates = [event for event in history if event.get("package_name") == name and event.get("verdict")]
    # run_scan records the current result before the AI endpoint is called. Skip one
    # identical leading record so the comparison describes an actual prior observation.
    if candidates:
        first = candidates[0]
        if (
            first.get("package_version") == current_version
            and first.get("verdict") == current_verdict
            and int(first.get("score") or 0) == current_score
        ):
            candidates = candidates[1:]
    if not candidates:
        return {
            "status": "FIRST_SEEN", "previous": None, "score_delta": None,
            "verdict_changed": False, "version_changed": False,
            "newly_activated_rules": [], "collector_regressions": [],
            "anomaly_score": None,
            "baseline": {"sample_count": 0, "median_score": None, "robust_z": None},
            "message": "비교할 이전 스캔이 없습니다.",
        }

    previous = candidates[0]
    previous_score = int(previous.get("score") or 0)
    previous_verdict = previous.get("verdict")
    score_delta = current_score - previous_score
    current_active = _active_rule_ids(scan.get("rules"))
    previous_active = _active_rule_ids(previous.get("rules"))
    current_tracks = scan.get("track_statuses") or {}
    previous_tracks = previous.get("track_statuses") or {}
    regressions = [
        track for track, old_status in previous_tracks.items()
        if old_status == "SUCCESS" and current_tracks.get(track) != "SUCCESS"
    ]
    worsened = _VERDICT_ORDER.get(str(current_verdict), 1) > _VERDICT_ORDER.get(str(previous_verdict), 1)
    historical_scores = [int(item.get("score") or 0) for item in candidates]
    median_score = float(median(historical_scores))
    deviations = [abs(value - median_score) for value in historical_scores]
    mad = float(median(deviations)) if deviations else 0.0
    if mad:
        robust_z = round(abs(current_score - median_score) / (1.4826 * mad), 2)
    else:
        robust_z = 0.0 if current_score == median_score else 8.0
    newly_activated = sorted(current_active - previous_active)
    anomaly_score = min(100, round(
        min(40.0, robust_z * 8)
        + (30 if worsened else 0)
        + min(20, len(regressions) * 10)
        + min(20, len(newly_activated) * 10)
    ))
    status = "REGRESSION" if worsened or regressions else (
        "CHANGED" if score_delta or current_version != previous.get("package_version") else "STABLE"
    )
    return {
        "status": status,
        "previous": {
            "version": previous.get("package_version"), "verdict": previous_verdict,
            "score": previous_score, "created_at": previous.get("created_at"),
        },
        "score_delta": score_delta,
        "verdict_changed": current_verdict != previous_verdict,
        "version_changed": current_version != previous.get("package_version"),
        "newly_activated_rules": newly_activated,
        "collector_regressions": sorted(regressions),
        "anomaly_score": anomaly_score,
        "baseline": {
            "sample_count": len(historical_scores), "median_score": median_score,
            "robust_z": robust_z,
        },
        "message": "이전 스캔 대비 악화가 감지되었습니다." if status == "REGRESSION" else "이전 스캔과 비교를 완료했습니다.",
    }


def scan_packages(
    packages: list[dict[str, Any]], *, max_workers: int = 6
) -> dict[str, Any]:
    """이미 정해진 (name, version) 목록을 OSV로 점검한다.

    ``monitor_project()``에서 조회 부분만 떼어낸 것이다. 설치 게이트 쪽은
    package.json이 아니라 lock 파일 전체(전이 의존성 포함)를 대상으로 삼아야
    해서 인벤토리 수집 단계를 공유할 수 없다. 조회 로직까지 따로 두면 두 경로의
    판정이 갈리므로 여기를 공통 지점으로 남긴다.

    querybatch로 취약 여부만 한 번에 확인한 뒤, 실제로 걸린 것에 한해서만
    상세를 병렬 조회한다 — 패키지가 수천 개여도 첫 왕복은 요청 1회다.
    """
    packages = [
        {"name": item["name"], "version": item["version"]}
        for item in packages if item.get("name") and item.get("version")
    ]
    if not packages:
        return {
            "ok": True, "status": "CLEAN", "package_count": 0,
            "vulnerable_count": 0, "error_count": 0, "packages": [],
        }
    try:
        batch = query_vulnerability_ids(packages)
    except Exception as exc:  # noqa: BLE001 - monitor must remain observable on API failure
        return {
            "ok": False, "status": "ERROR", "reason": f"{exc.__class__.__name__}: {exc}",
            "package_count": len(packages), "vulnerable_count": 0,
            "error_count": len(packages),
            "packages": [{**item, "status": "UNKNOWN", "count": 0} for item in packages],
        }

    detail_by_name: dict[str, dict[str, Any]] = {}
    vulnerable = [item for item in batch if item["ids"]]
    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, 12))) as executor:
        futures = {
            executor.submit(query_vulnerabilities, item["name"], item["version"]): item["name"]
            for item in vulnerable
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                detail_by_name[name] = future.result()
            except Exception as exc:  # pragma: no cover - query function already isolates
                detail_by_name[name] = {"status": "ERROR", "reason": str(exc), "count": 0}

    rows = []
    for item in batch:
        if item["ids"]:
            detail = detail_by_name.get(item["name"], {"status": "ERROR", "count": 0})
            rows.append({"name": item["name"], "version": item["version"], **detail})
        else:
            rows.append({
                "name": item["name"], "version": item["version"], "status": "CLEAN",
                "count": 0, "vulnerabilities": [], "recommended_version": None,
                "action": "조치 불필요",
            })
    vulnerable_rows = [row for row in rows if row.get("status") == "VULNERABLE"]
    error_rows = [row for row in rows if row.get("status") == "ERROR"]
    return {
        "ok": not error_rows,
        "status": "PARTIAL" if error_rows else ("ACTION_REQUIRED" if vulnerable_rows else "CLEAN"),
        "package_count": len(rows), "vulnerable_count": len(vulnerable_rows),
        "error_count": len(error_rows), "packages": rows,
    }


def monitor_project(project_dir: Path, *, max_workers: int = 6) -> dict[str, Any]:
    """Check exact installed direct dependencies and return actionable OSV results."""
    checked_at = datetime.now(timezone.utc).isoformat()
    inventory = collect_inventory(project_dir)
    if inventory is None:
        return {
            "ok": False, "status": "ERROR", "reason": "PACKAGE_JSON_NOT_FOUND",
            "project": str(project_dir), "checked_at": checked_at, "packages": [],
        }
    result = scan_packages(inventory["packages"], max_workers=max_workers)
    return {
        **result,
        "project": str(project_dir), "project_name": inventory.get("project"),
        "checked_at": checked_at, "advisory_only": True,
    }


__all__ = ["compare_scan_history", "monitor_project", "scan_packages"]
