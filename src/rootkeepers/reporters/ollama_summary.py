"""Opt-in, failure-isolated Ollama summary adapter."""

from __future__ import annotations

import os
from typing import Any, Mapping

import requests


def summarize_report(report: Mapping[str, Any]) -> dict[str, Any]:
    """Return a local-model summary or a non-fatal unavailable result."""
    if os.environ.get("ROOTKEEPERS_ENABLE_OLLAMA") != "1":
        return _unavailable("DISABLED")
    url = os.environ.get("ROOTKEEPERS_OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
    model = os.environ.get("ROOTKEEPERS_OLLAMA_MODEL", "llama3.2")
    timeout = float(os.environ.get("ROOTKEEPERS_OLLAMA_TIMEOUT_SECONDS", "20"))
    prompt = ("Summarize this package supply-chain security result in Korean. "
              "Do not change the verdict; list only evidence-backed concerns.\n" + str(dict(report)))
    try:
        response = requests.post(url, json={"model": model, "prompt": prompt, "stream": False}, timeout=timeout)
        response.raise_for_status()
        body = response.json()
        summary = body.get("response") if isinstance(body, dict) else None
        if not isinstance(summary, str) or not summary.strip():
            return _unavailable("INVALID_RESPONSE")
        return {"status": "SUCCESS", "model": model, "summary": summary.strip()}
    except (requests.RequestException, ValueError, TypeError) as error:
        return {"status": "UNAVAILABLE", "reason": "REQUEST_FAILED", "detail": str(error)}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "UNAVAILABLE", "reason": reason}
