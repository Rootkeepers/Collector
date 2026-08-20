"""Exhaustive local coverage for every detailed-rule signal branch."""

from __future__ import annotations

from copy import deepcopy

import pytest

from rootkeepers.interceptor.detailed_rule_engine import (
    evidence_from_lineage,
    evaluate_detailed_evidence,
)


def _base_evidence() -> dict:
    return {
        "orphan_release": {"commit_exists": True, "has_linked_pr": True, "governance_pr_baseline": True, "direct_push_prohibited": True, "new_author": False, "commit_signed": True, "immediate_tag": False},
        "unreviewed": {"has_pr": True, "review_governance_baseline": True, "human_approval_count": 2, "self_merge": False, "bot_only_approval": False, "external_approval": False},
        "workflow_drift": {"baseline_entry_points": [".github/workflows/release.yml"], "current_entry_point": ".github/workflows/release.yml", "workflow_modified_before_release": False},
        "oidc_mismatch": {"attestation_present": True, "baseline_attestation_present": True, "npm_repository": "owner/repo", "oidc_repository": "owner/repo", "provenance_entry_point": ".github/workflows/release.yml", "oidc_workflow": ".github/workflows/release.yml", "issuer": "https://token.actions.githubusercontent.com", "expected_issuers": ["https://token.actions.githubusercontent.com"], "official_runner": True},
        "unexpected_builder": {"baseline_attestations": [True, True, True], "current_attestation_present": True, "baseline_builder_id": "https://github.com/actions/runner/github-hosted", "current_builder_id": "https://github.com/actions/runner/github-hosted", "baseline_entry_point": ".github/workflows/release.yml", "current_entry_point": ".github/workflows/release.yml"},
        "tag_identity_drift": {"baseline_publishers": ["release-bot"], "current_publisher": "release-bot", "baseline_git_or_tag_present": True, "current_git_or_tag_present": True, "baseline_oidc_identity": "repo:owner/repo", "current_oidc_identity": "repo:owner/repo", "tag_pattern_mismatch": False},
    }


SIGNAL_CASES = [
    ("orphan_release", "commit_not_found", {"orphan_release": {"commit_exists": False}}),
    ("orphan_release", "missing_pr", {"orphan_release": {"has_linked_pr": False}}),
    ("orphan_release", "branch_protection_bypass", {"orphan_release": {"has_linked_pr": False, "direct_push_prohibited": True}}),
    ("orphan_release", "immediate_tag", {"orphan_release": {"has_linked_pr": False, "immediate_tag": True}}),
    ("orphan_release", "new_author", {"orphan_release": {"has_linked_pr": False, "new_author": True}}),
    ("orphan_release", "unsigned_commit", {"orphan_release": {"has_linked_pr": False, "commit_signed": False}}),
    ("unreviewed", "no_human_approval", {"unreviewed": {"human_approval_count": 0}}),
    ("unreviewed", "self_merge", {"unreviewed": {"human_approval_count": 0, "self_merge": True}}),
    ("unreviewed", "bot_only_approval", {"unreviewed": {"human_approval_count": 0, "bot_only_approval": True}}),
    ("unreviewed", "external_approval", {"unreviewed": {"human_approval_count": 0, "external_approval": True}}),
    ("workflow_drift", "workflow_absent", {"workflow_drift": {"current_entry_point": ""}}),
    ("workflow_drift", "entry_point_drift", {"workflow_drift": {"current_entry_point": ".github/workflows/other.yml"}}),
    ("workflow_drift", "workflow_modified_before_release", {"workflow_drift": {"workflow_modified_before_release": True}}),
    ("oidc_mismatch", "attestation_missing", {"oidc_mismatch": {"attestation_present": False}}),
    ("oidc_mismatch", "repository_mismatch", {"oidc_mismatch": {"oidc_repository": "attacker/repo"}}),
    ("oidc_mismatch", "workflow_identity_mismatch", {"oidc_mismatch": {"oidc_workflow": ".github/workflows/forged.yml"}}),
    ("oidc_mismatch", "issuer_mismatch", {"oidc_mismatch": {"issuer": "https://issuer.example"}}),
    ("oidc_mismatch", "unofficial_runner", {"oidc_mismatch": {"official_runner": False}}),
    ("unexpected_builder", "attestation_flip", {"unexpected_builder": {"current_attestation_present": False}}),
    ("unexpected_builder", "builder_changed", {"unexpected_builder": {"current_builder_id": "https://attacker.example/builder"}}),
    ("unexpected_builder", "entry_point_changed", {"unexpected_builder": {"current_entry_point": ".github/workflows/forged.yml"}}),
    ("tag_identity_drift", "publisher_drift", {"tag_identity_drift": {"current_publisher": "attacker"}}),
    ("tag_identity_drift", "git_tag_flip", {"tag_identity_drift": {"current_git_or_tag_present": False}}),
    ("tag_identity_drift", "oidc_identity_drift", {"tag_identity_drift": {"current_oidc_identity": "repo:attacker/repo"}}),
    ("tag_identity_drift", "tag_pattern_drift", {"tag_identity_drift": {"tag_pattern_mismatch": True}}),
]


@pytest.mark.parametrize(("rule_id", "signal_id", "updates"), SIGNAL_CASES)
def test_every_detailed_signal_is_emitted(rule_id: str, signal_id: str, updates: dict) -> None:
    evidence = deepcopy(_base_evidence())
    for rule, fields in updates.items():
        evidence[rule].update(fields)
    result = evaluate_detailed_evidence(evidence)
    rule = next(item for item in result["rules"] if item["id"] == rule_id)
    assert signal_id in {signal["id"] for signal in rule["signals"]}


def test_lineage_surfaces_nonstandard_runner_to_oidc_rule() -> None:
    report = {
        "tracks": {
            "npm": {"data": {"artifact": {"attestation": "PRESENT"}}},
            "sigstore": {"data": {"slsa_predicate": {"builder_id": "https://attacker.example/runner"}}},
        },
    }
    assert evidence_from_lineage(report)["oidc_mismatch"]["official_runner"] is False


def test_one_risk_rule_blocks_under_fail_closed_policy() -> None:
    evidence = _base_evidence()
    evidence["oidc_mismatch"]["oidc_repository"] = "attacker/repo"

    result = evaluate_detailed_evidence(evidence)

    assert result["verdict"] == "RISK"


def test_one_unverifiable_rule_is_reported_as_risk() -> None:
    evidence = _base_evidence()
    evidence["workflow_drift"]["baseline_entry_points"] = []

    result = evaluate_detailed_evidence(evidence)

    assert result["verdict"] == "UNVERIFIABLE (RISK)"
