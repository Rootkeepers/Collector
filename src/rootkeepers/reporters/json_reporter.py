"""Build a stable dashboard view without recomputing the security verdict."""

from __future__ import annotations

import json
from datetime import datetime, timezone
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
    package = _mapping(lineage, "package")
    tracks = _mapping(lineage, "tracks")
    sigstore = _mapping(_mapping(tracks, "sigstore"), "data")
    predicate = _mapping(sigstore, "slsa_predicate")
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package": {
            "ecosystem": package.get("ecosystem", "npm"),
            "name": package.get("name"),
            "version": package.get("version"),
        },
        "decision": {
            "verdict": risk.get("verdict", "UNVERIFIABLE (RISK)"),
            "total_score": risk.get("score", 0),
            "block_threshold": risk.get("threshold"),
            "rationale": risk.get("reason", "판정 근거가 제공되지 않았습니다."),
            "corroboration": dict(_mapping(risk, "corroboration")),
        },
        "rules": [_rule_view(rule) for rule in _list(risk, "rules")],
        "provenance": {
            "builder_identity": predicate.get("builder_id"),
            "workflow_path": predicate.get("workflow_path"),
            "repository": predicate.get("repository"),
            "commit": predicate.get("commit"),
            "track_statuses": dict(_mapping(_mapping(lineage, "summary"), "track_statuses")),
        },
        "tooling": {"packj": dict(packj) if packj is not None else _unavailable("DISABLED")},
        "ai_summary": dict(ai_summary) if ai_summary is not None else _unavailable("DISABLED"),
        "timings_ms": dict(timings_ms or {}),
    }


def write_dashboard_report(report: Mapping[str, Any], output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _rule_view(rule: Any) -> dict[str, Any]:
    item = rule if isinstance(rule, Mapping) else {}
    rule_id = str(item.get("id", "unknown"))
    rationale = str(item.get("reason", "근거가 제공되지 않았습니다."))
    prefix = {
        "orphan_release": "PR/승인 거버넌스 기준선과 현재 릴리스의 연결 정보를 비교했습니다. ",
        "workflow_drift": "워크플로 파일 경로 또는 내용 변화를 평가했습니다. ",
        "unexpected_builder": "Sigstore builder identity 변화를 평가했습니다. ",
    }.get(rule_id, "")
    return {
        "id": rule_id,
        "state": item.get("state", "UNVERIFIABLE"),
        "score": item.get("score", 0),
        "band": item.get("band", "UNVERIFIABLE"),
        "rationale": prefix + rationale,
        "signals": list(item.get("signals") or []),
        "evidence_status": item.get("evidence_status", "UNVERIFIABLE"),
        "evidence_limitations": list(item.get("evidence_limitations") or []),
    }


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    result = value.get(key)
    return result if isinstance(result, Mapping) else {}


def _list(value: Mapping[str, Any], key: str) -> list[Any]:
    result = value.get(key)
    return result if isinstance(result, list) else []


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "UNAVAILABLE", "reason": reason}


__all__ = ["build_dashboard_report", "write_dashboard_report", "SCHEMA_VERSION"]
