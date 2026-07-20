"""End-to-end tests for the unified release lineage pipeline."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env")

SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from rootkeepers.engine.lineage import collect_release_lineage_report


PACKAGE_NAME = "express"
PACKAGE_VERSION = "4.18.2"


@pytest.mark.e2e
def test_express_release_lineage_github_and_npm_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = os.getenv("E2E_GITHUB_TOKEN") or os.getenv("GITHUB_TOKEN")
    if not token:
        pytest.skip("E2E_GITHUB_TOKEN 또는 GITHUB_TOKEN이 필요합니다.")

    monkeypatch.setenv("GITHUB_TOKEN", token)

    report = collect_release_lineage_report(
        PACKAGE_NAME,
        PACKAGE_VERSION,
        sigstore_timeout=10,
    )

    track_statuses = report["summary"]["track_statuses"]
    assert track_statuses["npm"] == "SUCCESS"
    assert track_statuses["github"] == "SUCCESS"
