"""Opt-in legacy Ollama summary adapter isolated from the core verdict."""

from __future__ import annotations

import json
import os
from typing import Any, Mapping

import requests


def summarize_report(report: Mapping[str, Any]) -> dict[str, Any]:
    if os.environ.get("ROOTKEEPERS_ENABLE_OLLAMA") != "1":
        return _unavailable("DISABLED")
    url = os.environ.get("ROOTKEEPERS_OLLAMA_URL", "http://127.0.0.1:11434/api/generate")
    model = os.environ.get("ROOTKEEPERS_OLLAMA_MODEL", "llama3.2")
    try:
        timeout = max(1.0, float(os.environ.get("ROOTKEEPERS_OLLAMA_TIMEOUT_SECONDS", "20")))
    except ValueError:
        timeout = 20.0
    prompt = (
        "다음 공급망 보안 결과를 한국어로 요약하세요. verdict를 변경하거나 "
        "증거에 없는 사실을 추가하지 마세요.\n"
        + json.dumps(dict(report), ensure_ascii=False, default=str)
    )
    try:
        response = requests.post(
            url,
            json={"model": model, "prompt": prompt, "stream": False},
            timeout=timeout,
        )
        response.raise_for_status()
        body = response.json()
        summary = body.get("response") if isinstance(body, dict) else None
        if not isinstance(summary, str) or not summary.strip():
            return _unavailable("INVALID_RESPONSE")
        return {"status": "SUCCESS", "model": model, "summary": summary.strip()}
    except (requests.RequestException, ValueError, TypeError) as exc:
        return {**_unavailable("REQUEST_FAILED"), "detail": str(exc)}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "UNAVAILABLE", "reason": reason}


__all__ = ["summarize_report"]
