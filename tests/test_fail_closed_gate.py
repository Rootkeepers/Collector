from __future__ import annotations

from argparse import Namespace

from rootkeepers import cli
from rootkeepers.interceptor import safe_npm
from rootkeepers.interceptor.detailed_rule_engine import (
    DEFAULT_DETAILED_POLICY,
    DetailedRuleName,
    DetailedRuleResult,
    PackageDecision,
    RuleBand,
    _package_decision,
)


def test_gate_blocks_unverifiable(monkeypatch):
    monkeypatch.setattr(
        safe_npm,
        "check_package",
        lambda spec: safe_npm.RiskResult(spec, safe_npm.Verdict.UNVERIFIABLE, 0, "missing evidence"),
    )
    allowed, results = safe_npm.gate_install(["demo@1.0.0"])
    assert allowed is False
    assert results[0].verdict is safe_npm.Verdict.UNVERIFIABLE


def test_scan_returns_failure_for_unverifiable(monkeypatch):
    monkeypatch.setattr(
        safe_npm,
        "check_package",
        lambda spec: safe_npm.RiskResult(spec, safe_npm.Verdict.UNVERIFIABLE, 0, "missing evidence"),
    )
    monkeypatch.setattr(safe_npm, "report", lambda result: None)
    monkeypatch.setattr("rootkeepers.interceptor.reporting.flush_reports", lambda: None)

    assert cli.cmd_scan(Namespace(package=["demo@1.0.0"])) == 1


def _result(rule: DetailedRuleName, band: RuleBand, score: int = 0) -> DetailedRuleResult:
    return DetailedRuleResult(rule, score, band, (), band.value)


def test_authoritative_policy_blocks_one_risk_band():
    results = [
        _result(rule, RuleBand.RISK if index == 0 else RuleBand.PASS, 60 if index == 0 else 0)
        for index, rule in enumerate(DetailedRuleName)
    ]
    decision = _package_decision(42, [results[0]], results, DEFAULT_DETAILED_POLICY)
    assert decision is PackageDecision.RISK


def test_authoritative_policy_marks_any_missing_rule_as_risk():
    results = [
        _result(rule, RuleBand.UNVERIFIABLE if index == 0 else RuleBand.PASS)
        for index, rule in enumerate(DetailedRuleName)
    ]
    decision = _package_decision(0, [], results, DEFAULT_DETAILED_POLICY)
    assert decision.value == "UNVERIFIABLE (RISK)"
