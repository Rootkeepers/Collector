from rootkeepers.reporters.json_reporter import build_dashboard_report


def test_dashboard_report_has_explicit_rule_rationales_and_builder() -> None:
    lineage = {
        "package": {"ecosystem": "npm", "name": "example", "version": "1.0.0"},
        "summary": {"track_statuses": {"npm": "SUCCESS"}},
        "tracks": {"sigstore": {"data": {"slsa_predicate": {"builder_id": "https://builder/example", "workflow_path": ".github/workflows/release.yml"}}}},
    }
    risk = {
        "verdict": "RISK", "score": 75, "threshold": 60, "reason": "corroborated evidence",
        "corroboration": {"activated_rule_count": 3},
        "rules": [
            {"id": "orphan_release", "state": "MATCH", "score": 50, "band": "WARN", "reason": "no linked PR", "signals": []},
            {"id": "workflow_drift", "state": "MATCH", "score": 70, "band": "RISK", "reason": "path changed", "signals": []},
            {"id": "unexpected_builder", "state": "MATCH", "score": 70, "band": "RISK", "reason": "builder changed", "signals": []},
        ],
    }
    report = build_dashboard_report(lineage, risk)
    assert report["decision"]["total_score"] == 75
    assert report["provenance"]["builder_identity"] == "https://builder/example"
    assert "PR/승인 거버넌스" in report["rules"][0]["rationale"]
    assert "워크플로 파일 경로 또는 내용" in report["rules"][1]["rationale"]
    assert "builder identity" in report["rules"][2]["rationale"]
