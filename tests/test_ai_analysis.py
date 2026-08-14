from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from rootkeepers.analysis import graph as graph_module
from rootkeepers.analysis.monitoring import compare_scan_history, monitor_project
from rootkeepers.analysis.source_sast import UnsafeArchiveError, safe_extract_tarball, verify_sri
from rootkeepers.analysis.vulnerability import normalize_vulnerability


def _tarball(name: str, data: bytes, *, symlink: bool = False) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        info = tarfile.TarInfo(name)
        if symlink:
            info.type = tarfile.SYMTYPE
            info.linkname = "../../outside"
            archive.addfile(info)
        else:
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def test_safe_extract_accepts_regular_package_file(tmp_path: Path):
    root = safe_extract_tarball(_tarball("package/index.js", b"module.exports = 1"), tmp_path)
    assert root == tmp_path / "package"
    assert (root / "index.js").read_text() == "module.exports = 1"


@pytest.mark.parametrize("name,symlink", [("../../escape.js", False), ("package/link", True)])
def test_safe_extract_rejects_traversal_and_links(tmp_path: Path, name: str, symlink: bool):
    with pytest.raises(UnsafeArchiveError):
        safe_extract_tarball(_tarball(name, b"x", symlink=symlink), tmp_path)


def test_verify_sri_detects_match_and_mismatch():
    import base64
    import hashlib

    data = b"trusted artifact"
    digest = base64.b64encode(hashlib.sha512(data).digest()).decode()
    assert verify_sri(data, f"sha512-{digest}")["status"] == "VERIFIED"
    assert verify_sri(data, "sha512-invalid")["status"] == "MISMATCH"


def test_osv_normalization_extracts_fixed_versions():
    item = {
        "id": "GHSA-test",
        "summary": "test advisory",
        "affected": [{
            "package": {"ecosystem": "npm", "name": "demo"},
            "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
        }],
    }
    result = normalize_vulnerability(item, "demo")
    assert result["fixed_versions"] == ["1.2.3"]


def test_history_monitor_detects_regression():
    scan = {
        "package": {"name": "demo", "version": "2.0.0"},
        "verdict": "RISK", "score": 80,
        "rules": [{"id": "workflow_drift", "band": "RISK"}],
        "track_statuses": {"npm": "SUCCESS", "github": "ERROR"},
    }
    history = [
        {"package_name": "demo", "package_version": "2.0.0", "verdict": "RISK", "score": 80},
        {
            "package_name": "demo", "package_version": "1.0.0", "verdict": "PASS", "score": 0,
            "rules": [], "track_statuses": {"npm": "SUCCESS", "github": "SUCCESS"},
            "created_at": "2026-01-01T00:00:00+00:00",
        },
    ]
    result = compare_scan_history(scan, history)
    assert result["status"] == "REGRESSION"
    assert result["score_delta"] == 80
    assert result["collector_regressions"] == ["github"]
    assert result["anomaly_score"] >= 70
    assert result["baseline"]["sample_count"] == 1


def test_langgraph_analysis_preserves_core_verdict(monkeypatch):
    monkeypatch.setenv("TRUSTGATE_ENABLE_AI", "0")
    monkeypatch.setattr(
        graph_module, "query_vulnerabilities",
        lambda *_: {"status": "CLEAN", "count": 0, "vulnerabilities": [], "recommended_version": None},
    )
    monkeypatch.setattr(
        graph_module, "analyze_package_source",
        lambda *_: {"status": "CLEAN", "finding_count": 0, "findings": []},
    )
    scan = {
        "package": {"name": "demo", "version": "1.0.0"},
        "verdict": "RISK", "score": 90, "reason": "authoritative",
        "rules": [], "track_statuses": {},
    }
    result = graph_module.run_ai_analysis(scan, [])
    assert result["graph"]["engine"] == "langgraph"
    assert result["core_decision"] == {
        "verdict": "RISK", "score": 90, "reason": "authoritative", "unchanged": True,
    }
    assert result["llm"]["status"] == "DISABLED"


def test_groq_default_falls_back_locally_without_key(monkeypatch):
    monkeypatch.delenv("TRUSTGATE_AI_PROVIDER", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.setenv("TRUSTGATE_ENABLE_AI", "auto")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-must-not-be-used")
    monkeypatch.setattr(
        graph_module, "query_vulnerabilities",
        lambda *_: {
            "status": "VULNERABLE", "count": 1, "vulnerabilities": [{"id": "GHSA-test"}],
            "recommended_version": "1.0.1",
        },
    )
    monkeypatch.setattr(
        graph_module, "analyze_package_source",
        lambda *_: {"status": "CLEAN", "finding_count": 0, "findings": []},
    )
    scan = {
        "package": {"name": "demo", "version": "1.0.0"},
        "verdict": "RISK", "score": 100, "reason": "authoritative",
        "rules": [], "track_statuses": {},
    }

    result = graph_module.run_ai_analysis(scan, [])

    assert result["explanation"] == result["llm"]
    assert result["llm"]["status"] == "AVAILABLE"
    assert result["llm"]["provider"] == "local"
    assert result["llm"]["cost"] == "FREE"
    assert result["llm"]["network_required"] is False
    assert result["llm"]["fallback_from"] == "groq"
    assert result["llm"]["fallback_reason"] == "GROQ_API_KEY_MISSING"
    assert result["llm"]["confidence"] == "HIGH"
    assert result["core_decision"]["verdict"] == "RISK"


def test_groq_structured_provider(monkeypatch):
    monkeypatch.setenv("TRUSTGATE_AI_PROVIDER", "groq")
    monkeypatch.setenv("GROQ_API_KEY", "gsk-test")
    monkeypatch.setattr(
        graph_module, "query_vulnerabilities",
        lambda *_: {"status": "CLEAN", "count": 0, "vulnerabilities": [], "recommended_version": None},
    )
    monkeypatch.setattr(
        graph_module, "analyze_package_source",
        lambda *_: {"status": "CLEAN", "finding_count": 0, "findings": []},
    )

    captured = {}

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "choices": [{"message": {"content": json.dumps({
                    "headline": "정상",
                    "summary": "제공된 증거 기준 보조 분석입니다.",
                    "key_findings": ["알려진 취약점 없음"],
                    "recommended_actions": ["모니터링 유지"],
                    "confidence": "HIGH",
                }, ensure_ascii=False)}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140},
            }

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return Response()

    monkeypatch.setattr(graph_module.requests, "post", fake_post)
    scan = {
        "package": {"name": "demo", "version": "1.0.0"},
        "verdict": "PASS", "score": 0, "reason": "authoritative",
        "rules": [], "track_statuses": {},
    }

    result = graph_module.run_ai_analysis(scan, [])

    assert result["llm"]["provider"] == "groq"
    assert result["llm"]["status"] == "AVAILABLE"
    assert result["llm"]["cost"] == "FREE_TIER"
    assert captured["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert captured["kwargs"]["json"]["response_format"]["json_schema"]["strict"] is True
    assert captured["kwargs"]["json"]["store"] is False


def test_project_monitor_enriches_only_vulnerable_rows(tmp_path: Path, monkeypatch):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"bad": "1.0.0", "good": "1.0.0"}}))
    (tmp_path / "package-lock.json").write_text(json.dumps({
        "packages": {
            "node_modules/bad": {"version": "1.0.0"},
            "node_modules/good": {"version": "1.0.0"},
        }
    }))
    monkeypatch.setattr(
        "rootkeepers.analysis.monitoring.query_vulnerability_ids",
        lambda packages: [
            {"name": "bad", "version": "1.0.0", "ids": ["GHSA-test"]},
            {"name": "good", "version": "1.0.0", "ids": []},
        ],
    )
    monkeypatch.setattr(
        "rootkeepers.analysis.monitoring.query_vulnerabilities",
        lambda name, version: {
            "status": "VULNERABLE", "count": 1, "vulnerabilities": [{"id": "GHSA-test"}],
            "recommended_version": "1.0.1", "action": "upgrade",
        },
    )
    result = monitor_project(tmp_path)
    assert result["status"] == "ACTION_REQUIRED"
    assert result["vulnerable_count"] == 1
    assert {row["name"]: row["status"] for row in result["packages"]} == {
        "bad": "VULNERABLE", "good": "CLEAN",
    }
