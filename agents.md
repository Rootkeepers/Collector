# Collector engineering context

## Architecture and safety boundaries

- `interceptor/lineage.py` collects npm (Track A), GitHub (Track B), and Sigstore (Track C) evidence. Its result is the source of truth for provenance.
- `interceptor/detailed_rule_engine.py` produces the authoritative `PASS`, `RISK`, or `UNVERIFIABLE (RISK)` decision. Optional analysis must never change this verdict or block an install. The install gate is fail-closed: every non-`PASS` result is blocked.
- Package source is only unpacked into a temporary directory and is never installed or executed by Collector. External analyzers receive that directory only.

## Detection rules

1. `orphan_release`: a release lacks the PR/governance linkage expected from its historical baseline. It is not merely a missing PR; it is a deviation from established governance.
2. `unreviewed`: insufficient independent review evidence.
3. `workflow_drift`: GitHub Actions workflow file path or workflow content differs from the release baseline.
4. `oidc_mismatch`: Sigstore OIDC identity conflicts with the asserted release provenance.
5. `unexpected_builder`: the Sigstore SLSA builder identity differs from the historical builder baseline. This is distinct from workflow drift.
6. `tag_identity_drift`: release tag identity diverges from its baseline pattern.

## Zero-trust blocking policy

The default policy is fail-closed: one `RISK`-band rule blocks installation, and
one `UNVERIFIABLE` rule becomes `UNVERIFIABLE (RISK)` and also blocks
installation. The weighted score threshold of 75 and the 2/2 corroboration
settings remain dashboard-prioritization metadata; they do not override this
gate. `OIDC_MISMATCH` keeps weight 1.0; `WORKFLOW_DRIFT` and
`TAG_IDENTITY_DRIFT` use weights 0.8 and 0.6 to reduce reporting noise.

Local engine simulation on 2026-08-08 used `benign_300.csv` and
`malicious_attacks.csv`: all 300 baseline-consistent benign rows were `PASS`
with score 0, while all six simulated attacks were `RISK` with the independent
`orphan_release` and `oidc_mismatch` rules in the RISK band. This validates
the policy decision logic only; it does not replace live collector coverage.

All 25 detailed signal branches are covered by the local rule-engine matrix.
The OIDC `unofficial_runner` signal is populated from the Sigstore builder ID:
only the GitHub Actions runner namespace is classified as official; an absent
builder remains unverified rather than being treated as suspicious.

## Dashboard JSON contract (`rootkeepers.dashboard-report.v1`)

`package`, `decision`, `rules`, `provenance.builder_identity`, `tooling.packj`, and `ai_summary` are stable top-level dashboard inputs. Every rule has `id`, `state`, `score`, `band`, `rationale`, `signals`, and `evidence_status`. `decision.rationale` explains the total score. Optional tooling failures are represented in their own status field and never remove the core decision.

## Integrations

- packJ is enabled only when `ROOTKEEPERS_ENABLE_PACKJ=1`; its npm tarball download/extraction and analyzer adapter live in `collectors/npm/`. Configure its executable with `ROOTKEEPERS_PACKJ_COMMAND`. It analyzes a safely extracted tarball and must emit JSON on stdout.
- Ollama summarization is opt-in with `ROOTKEEPERS_ENABLE_OLLAMA=1` and lives in `reporters/ollama_summary.py`. `ROOTKEEPERS_OLLAMA_URL`, `ROOTKEEPERS_OLLAMA_MODEL`, and `ROOTKEEPERS_OLLAMA_TIMEOUT_SECONDS` control it. Failure or timeout yields `ai_summary.status=UNAVAILABLE`.
