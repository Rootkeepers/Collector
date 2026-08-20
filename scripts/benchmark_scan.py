"""Measure Collector stage timings for one or more pinned npm packages.

The script emits JSON Lines so runs can be compared without scraping console
output.  It never enables packJ or Ollama itself; set their opt-in environment
variables explicitly when measuring their cost.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from rootkeepers.interceptor.lineage import collect_release_lineage_report, evaluate_risk
from rootkeepers.collectors.npm.npm_source import scan_npm_package
from rootkeepers.reporters.ollama_summary import summarize_report
from rootkeepers.reporters.json_reporter import build_dashboard_report


def benchmark_one(package_spec: str) -> dict[str, object]:
    name, version = package_spec.rsplit("@", 1)
    total_started = time.perf_counter()
    started = time.perf_counter()
    lineage = collect_release_lineage_report(name, version)
    lineage_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    risk = evaluate_risk(lineage)
    rules_ms = (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    packj = scan_npm_package(name, version)
    packj_ms = (time.perf_counter() - started) * 1000
    dashboard = build_dashboard_report(lineage, risk, packj=packj)
    started = time.perf_counter()
    ai = summarize_report(dashboard)
    ai_ms = (time.perf_counter() - started) * 1000
    return {
        "package": package_spec,
        "verdict": risk["verdict"],
        "timings_ms": {"lineage": round(lineage_ms, 2), "rules": round(rules_ms, 2), "packj": round(packj_ms, 2), "ai": round(ai_ms, 2), "total": round((time.perf_counter() - total_started) * 1000, 2)},
        "track_statuses": lineage["summary"]["track_statuses"],
        "packj_status": packj["status"],
        "ai_status": ai["status"],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("packages_file", type=Path, help="one exact name@version per line")
    parser.add_argument("--output", type=Path, default=Path("benchmark-results.jsonl"))
    args = parser.parse_args()
    specs = [line.strip() for line in args.packages_file.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
    with args.output.open("w", encoding="utf-8") as stream:
        for spec in specs:
            try:
                result = benchmark_one(spec)
            except Exception as error:  # preserve benchmark progress after one failure
                result = {"package": spec, "status": "ERROR", "error": str(error)}
            stream.write(json.dumps(result, ensure_ascii=False) + "\n")
            print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
