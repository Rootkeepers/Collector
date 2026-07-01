import json

data = {
    "package": {
        "name": "",
        "version": "",
        "published_at": ""
    },

    "artifact": {
        "source": "npm",
        "integrity": "",
        "git_head": "",
        "attestation": ""
    },

    "workflow": {
        "id": "",
        "name": "",
        "repository": "",
        "run_id": "",
        "builder": ""
    },

    "commit": {
        "sha": "",
        "author": "",
        "timestamp": ""
    },

    "pull_request": {
        "number": None,
        "title": "",
        "merged": None,
        "merged_at": ""
    },

    "reviewers": [],

    "oidc": {
        "issuer": "",
        "subject": "",
        "repository": "",
        "workflow": ""
    },

    "lineage": {
        "artifact_to_workflow": "",
        "workflow_to_commit": "",
        "commit_to_pr": "",
        "pr_to_reviewer": "",
        "workflow_to_oidc": ""
    },

    "rules": {
        "orphan": False,
        "unreviewed": False,
        "workflow_drift": False,
        "oidc_mismatch": False,
        "unexpected_builder": False,
        "tag_drift": False
    },

    "baseline": {
        "versions_checked": 0,
        "similarity_score": 0.0
    },

    "result": {
        "trust_score": 0,
        "decision": ""
    }
}

with open("result.json", "w", encoding="utf-8") as f:
    json.dump(data, f, ensure_ascii=False, indent=4)