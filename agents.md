# Collector engineering context

## Architecture and safety boundaries

- `interceptor/lineage.py` collects npm (Track A), GitHub (Track B), and Sigstore (Track C) evidence. Its result is the source of truth for provenance.
- `interceptor/detailed_rule_engine.py` produces the authoritative `PASS`, `RISK`, or `UNVERIFIABLE` decision. Optional analysis must never change this verdict or block an install.
- Package source is only unpacked into a temporary directory and is never installed or executed by Collector. External analyzers receive that directory only.

## Detection rules

1. `orphan_release`: a release lacks the PR/governance linkage expected from its historical baseline. It is not merely a missing PR; it is a deviation from established governance.
2. `unreviewed`: insufficient independent review evidence.
3. `workflow_drift`: GitHub Actions workflow file path or workflow content differs from the release baseline.
4. `oidc_mismatch`: Sigstore OIDC identity conflicts with the asserted release provenance.
5. `unexpected_builder`: the Sigstore SLSA builder identity differs from the historical builder baseline. This is distinct from workflow drift.
6. `tag_identity_drift`: release tag identity diverges from its baseline pattern.

## Dashboard JSON contract (`rootkeepers.dashboard-report.v1`)

`package`, `decision`, `rules`, `provenance.builder_identity`, `tooling.packj`, and `ai_summary` are stable top-level dashboard inputs. Every rule has `id`, `state`, `score`, `band`, `rationale`, `signals`, and `evidence_status`. `decision.rationale` explains the total score. Optional tooling failures are represented in their own status field and never remove the core decision.

## Integrations

- packJ is enabled only when `ROOTKEEPERS_ENABLE_PACKJ=1`; its npm tarball download/extraction and analyzer adapter live in `collectors/npm/`. Configure its executable with `ROOTKEEPERS_PACKJ_COMMAND`. It analyzes a safely extracted tarball and must emit JSON on stdout.
- Ollama summarization is opt-in with `ROOTKEEPERS_ENABLE_OLLAMA=1` and lives in `reporters/ollama_summary.py`. `ROOTKEEPERS_OLLAMA_URL`, `ROOTKEEPERS_OLLAMA_MODEL`, and `ROOTKEEPERS_OLLAMA_TIMEOUT_SECONDS` control it. Failure or timeout yields `ai_summary.status=UNAVAILABLE`.

## Performance baseline

`scripts/benchmark_scan.py` records per-package Track A/B/C, rule evaluation, packJ, and optional AI timings as JSONL. On 2026-08-08, the benign control `lodash@4.17.21` completed in **47,289.74 ms** (lineage: 47,289.26 ms; rules: 0.41 ms; packJ disabled: 0.01 ms; Ollama disabled: 0 ms). npm and GitHub succeeded; Sigstore returned `ERROR`. This single cold-network sample is a diagnostic baseline, not a release threshold. At this rate, 300 serial packages would take roughly 3.94 hours before retries and optional tools; investigate network/Track C latency before setting a target.

## Validation

- Default CI runs only deterministic unit tests. `tests/test_live_malicious_packages.py` fetches the pinned `ua-parser-js@0.7.29` archive and runs static packJ analysis only when both `ROOTKEEPERS_RUN_LIVE_MALWARE_TESTS=1` and `ROOTKEEPERS_ENABLE_PACKJ=1` are set in an isolated environment. It must never run lifecycle scripts.
