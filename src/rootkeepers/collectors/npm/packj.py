"""Optional, failure-isolated adapter for the legacy packJ integration.

TrustGate's supported source analysis uses Semgrep. This adapter remains for
older integrations and is never invoked unless explicitly enabled.
"""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any


def scan_package_source(source_dir: Path, *, timeout_seconds: int = 120) -> dict[str, Any]:
    """Scan an inert source directory without executing package code."""
    if os.environ.get("ROOTKEEPERS_ENABLE_PACKJ") != "1":
        return _unavailable("DISABLED")
    if not source_dir.is_dir():
        return _unavailable("SOURCE_DIRECTORY_MISSING")

    configured = os.environ.get("ROOTKEEPERS_PACKJ_COMMAND", "packj").strip()
    command = shlex.split(configured, posix=os.name != "nt") if configured else []
    if not command:
        return _unavailable("COMMAND_MISSING")
    executable = shutil.which(command[0])
    if executable is None:
        return _unavailable("EXECUTABLE_NOT_FOUND")

    try:
        completed = subprocess.run(
            [executable, *command[1:], "scan", str(source_dir), "--output", "json"],
            check=False,
            capture_output=True,
            text=True,
            timeout=max(1, timeout_seconds),
        )
    except subprocess.TimeoutExpired:
        return _unavailable("TIMEOUT")
    except OSError as exc:
        return {**_unavailable("EXECUTION_ERROR"), "detail": str(exc)}

    if completed.returncode not in (0, 1):
        return {
            "status": "ERROR",
            "reason": "PACKJ_EXIT_NONZERO",
            "exit_code": completed.returncode,
            "findings": [],
            "stderr": completed.stderr[-1000:],
        }
    try:
        payload: Any = json.loads(completed.stdout)
    except (json.JSONDecodeError, TypeError):
        return {
            "status": "ERROR",
            "reason": "INVALID_JSON",
            "findings": [],
            "stderr": completed.stderr[-1000:],
        }

    findings = payload.get("findings", []) if isinstance(payload, dict) else []
    if not isinstance(findings, list):
        findings = []
    return {"status": "SUCCESS", "reason": None, "findings": findings, "raw": payload}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "UNAVAILABLE", "reason": reason, "findings": []}


__all__ = ["scan_package_source"]
