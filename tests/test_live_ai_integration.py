"""Opt-in OpenAI integration test.

This test intentionally makes one billable network request only when the caller
sets both ROOTKEEPERS_RUN_LIVE_AI_TESTS=1 and OPENAI_API_KEY.
"""

from __future__ import annotations

import os

import pytest

from rootkeepers.analysis import graph as graph_module


@pytest.mark.live_ai
def test_openai_structured_explanation_preserves_authoritative_verdict(monkeypatch):
    if os.getenv("ROOTKEEPERS_RUN_LIVE_AI_TESTS") != "1":
        pytest.skip("set ROOTKEEPERS_RUN_LIVE_AI_TESTS=1 to run the billable API test")
    if not os.getenv("OPENAI_API_KEY"):
        pytest.skip("OPENAI_API_KEY is required for the live API test")

    monkeypatch.setenv("TRUSTGATE_ENABLE_AI", "1")
    monkeypatch.setenv("TRUSTGATE_AI_PROVIDER", "openai")
    monkeypatch.setattr(
        graph_module,
        "query_vulnerabilities",
        lambda *_: {
            "status": "VULNERABLE",
            "count": 1,
            "vulnerabilities": [
                {"id": "GHSA-test", "summary": "synthetic integration-test advisory"}
            ],
            "recommended_version": "1.0.1",
        },
    )
    monkeypatch.setattr(
        graph_module,
        "analyze_package_source",
        lambda *_: {
            "status": "CLEAN",
            "finding_count": 0,
            "findings": [],
            "integrity": {"status": "VERIFIED"},
        },
    )
    scan = {
        "package": {"name": "synthetic-demo", "version": "1.0.0"},
        "verdict": "RISK",
        "score": 100,
        "reason": "synthetic authoritative decision",
        "rules": [{"id": "oidc_mismatch", "band": "RISK", "score": 100}],
        "track_statuses": {"npm": "SUCCESS", "github": "SUCCESS", "sigstore": "SUCCESS"},
    }

    result = graph_module.run_ai_analysis(scan, [])

    assert result["llm"]["status"] == "AVAILABLE", result["llm"].get("reason")
    assert result["llm"]["provider"] == "openai"
    assert result["llm"]["headline"]
    assert result["llm"]["summary"]
    assert result["llm"]["confidence"] in {"LOW", "MEDIUM", "HIGH"}
    assert result["core_decision"] == {
        "verdict": "RISK",
        "score": 100,
        "reason": "synthetic authoritative decision",
        "unchanged": True,
    }
