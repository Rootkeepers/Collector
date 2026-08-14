"""Opt-in Groq Free tier integration test."""

from __future__ import annotations

import os

import pytest

from rootkeepers.analysis import graph as graph_module


@pytest.mark.live_groq
def test_groq_free_structured_explanation_preserves_authoritative_verdict(monkeypatch):
    if os.getenv("ROOTKEEPERS_RUN_LIVE_GROQ_TESTS") != "1":
        pytest.skip("set ROOTKEEPERS_RUN_LIVE_GROQ_TESTS=1 to call the Groq Free tier API")
    if not os.getenv("GROQ_API_KEY"):
        pytest.skip("GROQ_API_KEY is required for the live Groq test")

    monkeypatch.setenv("TRUSTGATE_ENABLE_AI", "1")
    monkeypatch.setenv("TRUSTGATE_AI_PROVIDER", "groq")
    monkeypatch.setattr(
        graph_module,
        "query_vulnerabilities",
        lambda *_: {
            "status": "VULNERABLE", "count": 1,
            "vulnerabilities": [{"id": "GHSA-test", "summary": "synthetic advisory"}],
            "recommended_version": "1.0.1",
        },
    )
    monkeypatch.setattr(
        graph_module,
        "analyze_package_source",
        lambda *_: {
            "status": "CLEAN", "finding_count": 0, "findings": [],
            "artifact": {"integrity": {"status": "VERIFIED"}},
        },
    )
    scan = {
        "package": {"name": "synthetic-demo", "version": "1.0.0"},
        "verdict": "RISK", "score": 100, "reason": "synthetic authoritative decision",
        "rules": [{"id": "oidc_mismatch", "band": "RISK", "score": 100}],
        "track_statuses": {"npm": "SUCCESS", "github": "SUCCESS", "sigstore": "SUCCESS"},
    }

    result = graph_module.run_ai_analysis(scan, [])

    assert result["llm"]["status"] == "AVAILABLE", result["llm"].get("fallback_reason")
    assert result["llm"]["provider"] == "groq"
    assert result["llm"]["cost"] == "FREE_TIER"
    assert result["llm"]["headline"]
    assert result["llm"]["summary"]
    assert result["llm"]["confidence"] in {"LOW", "MEDIUM", "HIGH"}
    assert result["core_decision"] == {
        "verdict": "RISK", "score": 100,
        "reason": "synthetic authoritative decision", "unchanged": True,
    }
