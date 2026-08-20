"""Explicitly opt-in live static scan; never executes package code."""

import json
import os
from pathlib import Path

import pytest

from rootkeepers.collectors.npm.npm_source import scan_npm_package


@pytest.mark.live_malware
def test_packj_scans_a_pinned_real_world_malicious_package() -> None:
    if os.environ.get("ROOTKEEPERS_RUN_LIVE_MALWARE_TESTS") != "1":
        pytest.skip("set ROOTKEEPERS_RUN_LIVE_MALWARE_TESTS=1 in an isolated environment")
    if os.environ.get("ROOTKEEPERS_ENABLE_PACKJ") != "1":
        pytest.skip("set ROOTKEEPERS_ENABLE_PACKJ=1 after installing packJ")
    case = json.loads((Path(__file__).parent / "data" / "real_world_malicious_packages.json").read_text(encoding="utf-8"))[0]
    result = scan_npm_package(case["name"], case["version"])
    assert result["status"] == "SUCCESS", result
