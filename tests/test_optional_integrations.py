import json
from types import SimpleNamespace

from rootkeepers.collectors.npm import packj
from rootkeepers.reporters import ollama_summary as ollama


def test_packj_is_disabled_by_default(monkeypatch, tmp_path) -> None:
    monkeypatch.delenv("ROOTKEEPERS_ENABLE_PACKJ", raising=False)
    assert packj.scan_package_source(tmp_path)["reason"] == "DISABLED"


def test_packj_normalizes_json(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ROOTKEEPERS_ENABLE_PACKJ", "1")
    monkeypatch.setattr(packj.shutil, "which", lambda _: "packj")
    monkeypatch.setattr(packj.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=json.dumps({"findings": [{"id": "x"}]}), stderr=""))
    result = packj.scan_package_source(tmp_path)
    assert result["status"] == "SUCCESS"
    assert result["findings"] == [{"id": "x"}]


def test_ollama_failure_is_nonfatal(monkeypatch) -> None:
    monkeypatch.setenv("ROOTKEEPERS_ENABLE_OLLAMA", "1")
    monkeypatch.setattr(ollama.requests, "post", lambda *args, **kwargs: (_ for _ in ()).throw(ollama.requests.ConnectionError("offline")))
    result = ollama.summarize_report({"decision": {"verdict": "PASS"}})
    assert result["status"] == "UNAVAILABLE"
    assert result["reason"] == "REQUEST_FAILED"
