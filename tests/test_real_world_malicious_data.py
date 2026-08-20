import json
from pathlib import Path


def test_real_world_malicious_package_cases_are_pinned_and_sourced() -> None:
    cases = json.loads((Path(__file__).parent / "data" / "real_world_malicious_packages.json").read_text(encoding="utf-8"))
    assert cases
    assert all(case["name"] and case["version"] and case["source"].startswith("https://github.com/advisories/") for case in cases)
