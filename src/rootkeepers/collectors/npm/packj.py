"""Safe packJ adapter with a JSON-only contract."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any


def scan_package_source(source_dir: Path, *, timeout_seconds: int = 120) -> dict[str, Any]:
    """Run packJ against an already extracted package without executing it.

    The adapter intentionally accepts a directory rather than calling npm; the
    caller owns secure download/extraction and tests can inject a temp folder.
    Set ``ROOTKEEPERS_PACKJ_COMMAND`` when the local packJ installation uses a
    different command-line syntax.
    """
    if os.environ.get("ROOTKEEPERS_ENABLE_PACKJ") != "1":
        return _unavailable("DISABLED")
    command = os.environ.get("ROOTKEEPERS_PACKJ_COMMAND", "packj")
    executable = shutil.which(command)
    if executable is None:
        return _unavailable("EXECUTABLE_NOT_FOUND")
    try:
        completed = subprocess.run(
            [executable, "scan", str(source_dir), "--output", "json"],
            check=False, capture_output=True, text=True, timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired:
        return _unavailable("TIMEOUT")
    except OSError as error:
        return _unavailable(f"EXECUTION_ERROR: {error}")
    if completed.returncode not in (0, 1):
        return {"status": "ERROR", "reason": "PACKJ_EXIT_NONZERO", "exit_code": completed.returncode, "findings": [], "stderr": completed.stderr[-1000:]}
    try:
        payload: Any = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return {"status": "ERROR", "reason": "INVALID_JSON", "findings": [], "stderr": completed.stderr[-1000:]}
    findings = payload.get("findings", []) if isinstance(payload, dict) else []
    return {"status": "SUCCESS", "reason": None, "findings": findings if isinstance(findings, list) else [], "raw": payload}


def _unavailable(reason: str) -> dict[str, Any]:
    return {"status": "UNAVAILABLE", "reason": reason, "findings": []}
