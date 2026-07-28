"""Run the six detailed supply-chain rules against a benign npm CSV corpus.

The script intentionally calls the same npm/GitHub/Sigstore lineage pipeline
as the interceptor.  It is an integration verifier, not a mocked unit test.

Example:
    python scripts/verify_benign_csv.py C:/Users/iljae/Downloads/benign_300.csv \
        --strict --output benign-results.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from rootkeepers.interceptor.detailed_rule_engine import evidence_from_lineage
from rootkeepers.interceptor.lineage import collect_release_lineage_report, evaluate_risk


RULE_IDS = (
    "orphan_release",
    "unreviewed",
    "workflow_drift",
    "oidc_mismatch",
    "unexpected_builder",
    "tag_identity_drift",
)


def read_package_specs(path: Path, limit: int | None) -> list[tuple[str, str]]:
    """Read unique package/version pairs from the supplied corpus CSV."""
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"package", "version"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("CSV must contain package and version columns")
        specs: list[tuple[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for row in reader:
            package = (row.get("package") or "").strip()
            version = (row.get("version") or "").strip()
            spec = (package, version)
            if not package or not version or spec in seen:
                continue
            seen.add(spec)
            specs.append(spec)
            if limit is not None and len(specs) >= limit:
                break
    return specs


def evaluate_package(package: str, version: str, sigstore_timeout: int) -> dict[str, Any]:
    """Collect lineage and retain a compact, audit-friendly rule result."""
    spec = f"{package}@{version}"
    try:
        lineage = collect_release_lineage_report(
            package, version, sigstore_timeout=sigstore_timeout
        )
        result = evaluate_risk(lineage)
        evidence = evidence_from_lineage(lineage)
        rules = {rule["id"]: rule for rule in result["rules"]}
        missing_rules = [rule_id for rule_id in RULE_IDS if rule_id not in rules]
        return {
            "package": package,
            "version": version,
            "spec": spec,
            "error": None,
            "tracks": lineage["summary"]["track_statuses"],
            "baseline": {
                "npm_release_count": len(lineage.get("baseline", {}).get("npm", {}).get("releases", [])),
                "github_release_count": len(lineage.get("baseline", {}).get("github", {}).get("releases", [])),
            },
            "coverage": _coverage(evidence),
            "verdict": result["verdict"],
            "score": result["score"],
            "missing_rule_ids": missing_rules,
            "rules": [
                {
                    "id": rule_id,
                    "band": rules[rule_id]["band"],
                    "score": rules[rule_id]["score"],
                    "reason": rules[rule_id]["reason"],
                    "evidence_status": rules[rule_id].get("evidence_status"),
                    "evidence_limitations": rules[rule_id].get("evidence_limitations", []),
                    "signals": rules[rule_id]["signals"],
                }
                for rule_id in RULE_IDS
                if rule_id in rules
            ],
        }
    except Exception as error:  # Retain the failed sample and continue the corpus.
        return {
            "package": package,
            "version": version,
            "spec": spec,
            "error": {"type": type(error).__name__, "message": str(error)},
            "tracks": {},
            "baseline": {},
            "coverage": {rule_id: False for rule_id in RULE_IDS},
            "verdict": None,
            "score": None,
            "missing_rule_ids": list(RULE_IDS),
            "rules": [],
        }


def _coverage(evidence: dict[str, Any]) -> dict[str, bool]:
    """Report whether each rule received its required current/history inputs."""
    return {
        "orphan_release": evidence["orphan_release"].get("has_linked_pr") is not None
        and evidence["orphan_release"].get("governance_pr_baseline") is not None,
        "unreviewed": evidence["unreviewed"].get("has_pr") is not None
        and evidence["unreviewed"].get("review_governance_baseline") is not None,
        "workflow_drift": bool(evidence["workflow_drift"].get("baseline_entry_points")),
        "oidc_mismatch": evidence["oidc_mismatch"].get("attestation_present") is not None,
        "unexpected_builder": bool(evidence["unexpected_builder"].get("baseline_attestations"))
        and bool(evidence["unexpected_builder"].get("baseline_builder_id"))
        and bool(evidence["unexpected_builder"].get("current_builder_id")),
        "tag_identity_drift": bool(evidence["tag_identity_drift"].get("baseline_publishers"))
        and bool(evidence["tag_identity_drift"].get("current_publisher")),
    }


def run_corpus(
    specs: Iterable[tuple[str, str]], *, workers: int, sigstore_timeout: int
) -> list[dict[str, Any]]:
    """Evaluate samples concurrently; keep result ordering deterministic."""
    ordered_specs = list(specs)
    results: dict[tuple[str, str], dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(evaluate_package, package, version, sigstore_timeout): (package, version)
            for package, version in ordered_specs
        }
        for future in as_completed(futures):
            package, version = futures[future]
            results[(package, version)] = future.result()
            print(f"completed {package}@{version}", flush=True)
    return [results[spec] for spec in ordered_specs]


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize every rule and every detailed signal across the corpus."""
    bands = {rule_id: Counter() for rule_id in RULE_IDS}
    signals = {rule_id: Counter() for rule_id in RULE_IDS}
    track_statuses: Counter[str] = Counter()
    errors = 0
    missing_rules = 0
    coverage = {rule_id: Counter() for rule_id in RULE_IDS}
    for sample in results:
        errors += sample["error"] is not None
        missing_rules += len(sample["missing_rule_ids"])
        track_statuses.update(sample["tracks"].values())
        for rule_id, covered in sample["coverage"].items():
            coverage[rule_id]["covered" if covered else "missing"] += 1
        for rule in sample["rules"]:
            bands[rule["id"]][rule["band"]] += 1
            signals[rule["id"]].update(signal["id"] for signal in rule["signals"])
    return {
        "samples": len(results),
        "collection_errors": errors,
        "missing_rule_results": missing_rules,
        "track_statuses": dict(sorted(track_statuses.items())),
        "rule_bands": {rule_id: dict(sorted(counts.items())) for rule_id, counts in bands.items()},
        "detailed_signals": {rule_id: dict(sorted(counts.items())) for rule_id, counts in signals.items()},
        "rule_input_coverage": {rule_id: dict(sorted(counts.items())) for rule_id, counts in coverage.items()},
    }


def strict_failures(results: list[dict[str, Any]]) -> list[str]:
    """Return violations for a corpus expected to be benign and fully covered."""
    failures: list[str] = []
    for sample in results:
        if sample["error"]:
            failures.append(f"{sample['spec']}: collection error")
            continue
        bad_tracks = [name for name, status in sample["tracks"].items() if status != "SUCCESS"]
        if bad_tracks:
            failures.append(f"{sample['spec']}: non-success tracks: {', '.join(bad_tracks)}")
        if sample["missing_rule_ids"]:
            failures.append(f"{sample['spec']}: missing rules: {', '.join(sample['missing_rule_ids'])}")
        for rule in sample["rules"]:
            if rule["band"] != "PASS" or rule["signals"]:
                failures.append(f"{sample['spec']}: {rule['id']}={rule['band']}")
            if rule.get("evidence_status") != "COMPLETE":
                failures.append(
                    f"{sample['spec']}: {rule['id']} evidence={rule.get('evidence_status')}"
                )
        uncovered = [rule_id for rule_id, covered in sample["coverage"].items() if not covered]
        if uncovered:
            failures.append(f"{sample['spec']}: incomplete evidence: {', '.join(uncovered)}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_path", type=Path)
    parser.add_argument("--limit", type=int, help="Evaluate only the first N unique rows")
    parser.add_argument("--workers", type=int, default=1, help="Concurrent packages (default: 1)")
    parser.add_argument("--sigstore-timeout", type=int, default=30)
    parser.add_argument("--output", type=Path, help="Write the complete JSON report here")
    parser.add_argument("--strict", action="store_true", help="Fail if any track/rule is not a clean PASS")
    args = parser.parse_args()
    if args.limit is not None and args.limit < 1:
        parser.error("--limit must be positive")
    if args.workers < 1:
        parser.error("--workers must be positive")

    specs = read_package_specs(args.csv_path, args.limit)
    if not specs:
        parser.error("CSV did not contain package/version samples")
    results = run_corpus(specs, workers=args.workers, sigstore_timeout=args.sigstore_timeout)
    report = {"summary": summarize(results), "samples": results}
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    if args.output:
        args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"wrote {args.output}")

    failures = strict_failures(results) if args.strict else []
    if failures:
        print("strict failures:", *failures, sep="\n", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
