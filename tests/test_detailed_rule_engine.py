from rootkeepers.interceptor.detailed_rule_engine import (
    evaluate_detailed_evidence,
    evidence_from_lineage,
)


def test_every_detailed_signal_is_reachable() -> None:
    result = evaluate_detailed_evidence(
        {
            "orphan_release": {
                "has_linked_pr": False,
                "governance_pr_baseline": True,
                "direct_push_prohibited": True,
                "immediate_tag": True,
                "new_author": True,
                "commit_signed": False,
            },
            "unreviewed": {
                "has_pr": True,
                "review_governance_baseline": True,
                "human_approval_count": 0,
                "self_merge": True,
                "bot_only_approval": True,
                "external_approval": True,
            },
            "workflow_drift": {
                "baseline_entry_points": [".github/workflows/release.yml"],
                "current_entry_point": ".github/workflows/other.yml",
            },
            "oidc_mismatch": {
                "attestation_present": True,
                "npm_repository": "github.com/acme/npm-repo",
                "oidc_repository": "github.com/acme/other-repo",
                "provenance_entry_point": ".github/workflows/a.yml",
                "oidc_workflow": ".github/workflows/b.yml",
                "issuer": "https://untrusted.example",
                "expected_issuers": ["https://token.actions.githubusercontent.com"],
                "official_runner": False,
            },
            "unexpected_builder": {
                "baseline_attestations": [True, True, True],
                "current_attestation_present": True,
                "baseline_builder_id": "https://builder/old",
                "current_builder_id": "https://builder/new",
            },
            "tag_identity_drift": {
                "baseline_publishers": ["trusted-publisher"],
                "current_publisher": "new-publisher",
                "publisher_has_no_history": True,
                "baseline_git_or_tag_present": True,
                "current_git_or_tag_present": False,
                "baseline_oidc_identity": "old-subject",
                "current_oidc_identity": "new-subject",
                "tag_pattern_mismatch": True,
            },
        }
    )
    signal_ids = {
        rule["id"]: {signal["id"] for signal in rule["signals"]}
        for rule in result["rules"]
    }
    assert signal_ids == {
        "orphan_release": {"missing_pr", "branch_protection_bypass", "immediate_tag", "new_author", "unsigned_commit"},
        "unreviewed": {"no_human_approval", "self_merge", "bot_only_approval", "external_approval"},
        "workflow_drift": {"entry_point_drift"},
        "oidc_mismatch": {"repository_mismatch", "workflow_identity_mismatch", "issuer_mismatch", "unofficial_runner"},
        "unexpected_builder": {"builder_changed"},
        "tag_identity_drift": {"publisher_drift", "git_tag_flip", "oidc_identity_drift", "tag_pattern_drift"},
    }


def test_lineage_mapping_uses_historical_sigstore_and_exact_npm_versions() -> None:
    report = {
        "pipeline": {"npm_to_github": {"github_lookup": {"git_head": "current-sha"}}},
        "tracks": {
            "npm": {"data": {"artifact": {"attestation": "PRESENT", "publisher": "alice", "repo_url": "https://github.com/acme/pkg"}, "package": {"published_at": "2026-01-01T00:01:00+00:00"}}},
            "github": {"data": {"commit": {"author_login": "alice", "timestamp": "2026-01-01T00:00:00+00:00", "signed": True, "pull_requests": []}, "tags": [], "workflow_modified_before_release": False}},
            "sigstore": {"data": {"slsa_predicate": {"builder_id": "new-builder", "workflow_path": ".github/workflows/release.yml"}, "fulcio_oidc": {"subject": "new-subject"}}},
        },
        "baseline": {
            "npm": {"publishers": ["alice"], "attestations_present": [True], "releases": [{"version": "1.0.0", "sigstore": {"data": {"slsa_predicate": {"builder_id": "old-builder", "workflow_path": ".github/workflows/release.yml"}, "fulcio_oidc": {"subject": "old-subject"}}}}]},
            "github": {"releases": [{"version": "1.0.0", "commit": {"author_login": "alice", "pull_requests": []}, "tags": [{"name": "v1.0.0"}], "workflow_entry_points": [".github/workflows/release.yml"]}]},
        },
    }
    evidence = evidence_from_lineage(report)
    assert evidence["unexpected_builder"]["baseline_builder_id"] == "old-builder"
    assert evidence["unexpected_builder"]["current_builder_id"] == "new-builder"
    assert evidence["tag_identity_drift"]["baseline_oidc_identity"] == "old-subject"
    assert evidence["tag_identity_drift"]["current_git_or_tag_present"] is True
    assert evidence["unreviewed"]["review_governance_baseline"] is False


def test_common_benign_drift_combination_is_not_blocked() -> None:
    """Workflow/OIDC drift remains visible but cannot alone block install."""
    result = evaluate_detailed_evidence(
        {
            "workflow_drift": {
                "baseline_entry_points": [".github/workflows/release.yml"],
                "current_entry_point": ".github/workflows/publish.yml",
            },
            "oidc_mismatch": {
                "attestation_present": True,
                "npm_repository": "github.com/acme/pkg",
                "oidc_repository": "github.com/acme/pkg",
                "provenance_entry_point": ".github/workflows/publish.yml",
                "oidc_workflow": ".github/workflows/release.yml",
            },
        }
    )
    assert result["score"] == 100
    assert result["verdict"] == "PASS"
    assert result["corroboration"] == {
        "activated_rule_count": 2,
        "risk_band_rule_count": 0,
        "bonus": 10,
        "minimum_required": 3,
        "minimum_risk_band_required": 3,
    }
