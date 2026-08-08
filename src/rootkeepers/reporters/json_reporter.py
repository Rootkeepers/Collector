"""Dashboard-oriented JSON report builder.

This layer deliberately does not recompute security decisions.  It makes the
lineage/rule-engine output stable and easy for a front end to consume.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Mapping

SCHEMA_VERSION = "rootkeepers.dashboard-report.v1"


def build_dashboard_report(
    lineage: Mapping[str, Any],
    risk: Mapping[str, Any],
    *,
    packj: Mapping[str, Any] | None = None,
    ai_summary: Mapping[str, Any] | None = None,
    timings_ms: Mapping[str, float] | None = None,
) -> dict[str, Any]:
    """Return a stable, dashboard-friendly view of one package analysis."""
    package = _mapping(lineage, "package")
    tracks = _mapping(lineage, "tracks")
    sigstore = _mapping(_mapping(tracks, "sigstore"), "data")
    predicate = _mapping(sigstore, "slsa_predicate")
    rules = [_rule_view(rule) for rule in _list(risk, "rules")]
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package": {
            "ecosystem": package.get("ecosystem", "npm"),
            "name": package.get("name"),
            "version": package.get("version"),
        },
        "decision": {
            "verdict": risk.get("verdict", "UNVERIFIABLE"),
            "total_score": risk.get("score", 0),
            "block_threshold": risk.get("threshold"),
            "rationale": risk.get("reason", "판정 근거가 제공되지 않았습니다."),
            "corroboration": _mapping(risk, "corroboration"),
        },
        "rules": rules,
        "provenance": {
            "builder_identity": predicate.get("builder_id"),
            "workflow_path": predicate.get("workflow_path"),
            "repository": predicate.get("repository"),
            "commit": predicate.get("commit"),
            "track_statuses": _mapping(_mapping(lineage, "summary"), "track_statuses"),
        },
        "tooling": {"packj": dict(packj or _unavailable("DISABLED"))},
        "ai_summary": dict(ai_summary or _unavailable("DISABLED")),
        "timings_ms": dict(timings_ms or {}),
    }


def write_dashboard_report(report: Mapping[str, Any], output_path: Path) -> None:
    """Write UTF-8 JSON for dashboard ingestion; callers choose the location."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def _rule_view(rule: Any) -> dict[str, Any]:
    item = rule if isinstance(rule, Mapping) else {}
    rule_id = str(item.get("id", "unknown"))
    rationale = str(item.get("reason", "근거가 제공되지 않았습니다."))
    if rule_id == "orphan_release":
        rationale = (
            "Rule 1 (Orphan Release): 과거 릴리스의 PR/승인 거버넌스 기준선과 "
            "현재 릴리스의 연결 정보를 비교했습니다. " + rationale
        )
    elif rule_id == "workflow_drift":
        rationale = "Rule 3 (Workflow Drift): 워크플로 파일 경로 또는 내용 변화 평가. " + rationale
    elif rule_id == "unexpected_builder":
        rationale = "Rule 5 (Unexpected Builder): Sigstore builder identity 변화 평가. " + rationale
    return {
        "id": rule_id,
        "state": item.get("state", "UNVERIFIABLE"),
        "score": item.get("score", 0),
        "band": item.get("band", "UNVERIFIABLE"),
        "rationale": rationale,
        "signals": list(item.get("signals", [])),
        "evidence_status": item.get("evidence_status", "UNVERIFIABLE"),
        "evidence_limitations": list(item.get("evidence_limitations", [])),
    }


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "UNAVAILABLE", "reason": reason, "findings": []}


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    result = value.get(key)
    return result if isinstance(result, Mapping) else {}


def _list(value: Mapping[str, Any], key: str) -> list[Any]:
    result = value.get(key)
    return result if isinstance(result, list) else []
