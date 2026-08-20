from pathlib import Path


APP_JS = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "rootkeepers"
    / "dashboard"
    / "static"
    / "app.js"
)


def test_dashboard_explains_the_authoritative_fail_closed_policy() -> None:
    source = APP_JS.read_text(encoding="utf-8")

    assert "fail-closed · RISK 1개 또는 검증 불가 1개부터 설치 차단/보류" in source
    assert "RISK 밴드 <b>${p.decision.riskBandCount}</b>개 (1개 이상 설치 차단)" in source
    assert "검증 불가 <b>${p.decision.unverifiableCount}</b>개 (1개 이상 설치 보류)" in source
    assert "보고 기준 ${BLOCK_THRESHOLD}" not in source
    assert "MIN_CORROBORATING" not in source
    assert "MIN_RISK_BAND" not in source


def test_dashboard_reconstructs_rule_band_counts_for_live_and_stored_scans() -> None:
    source = APP_JS.read_text(encoding="utf-8")

    assert source.count("const bandCounts = summarizeRuleBands(rules);") == 2
    assert "unverifiableCount: values.filter(rule => rule.band === 'UNVERIFIABLE').length" in source
    assert "activatedCount: 0, riskBandCount: 0" not in source


def test_dashboard_does_not_describe_collected_baselines_as_unimplemented() -> None:
    source = APP_JS.read_text(encoding="utf-8")

    assert "미구현 기능" not in source
    assert "python webapp/server.py" not in source
    assert "trustgate up" in source
