"""Utilities for extracting normalized fields from SLSA predicates."""

from typing import Any


def _safe_get_mapping(value: Any, key: str) -> dict:
    """Return a nested dictionary value when present, otherwise an empty dict."""
    if not isinstance(value, dict):
        return {}

    nested = value.get(key)
    if isinstance(nested, dict):
        return nested

    return {}


def _safe_get_string(value: Any, key: str) -> str:
    """Return a string field when present, otherwise an empty string."""
    if not isinstance(value, dict):
        return ""

    nested = value.get(key)
    if isinstance(nested, str):
        return nested

    return ""


def parse_slsa_predicate(predicate: dict) -> dict:
    """Extract core provenance fields from a parsed SLSA predicate.

    The returned dictionary always contains the repository, commit, workflow
    path, and SLSA builder identity. Missing or malformed
    fields are represented as empty strings instead of raising exceptions.
    """
    result = {
        "repository": "",
        "commit": "",
        "workflow_path": "",
        "builder_id": "",
    }

    if not isinstance(predicate, dict):
        return result

    build_definition = _safe_get_mapping(predicate, "buildDefinition")
    external_parameters = _safe_get_mapping(build_definition, "externalParameters")

    workflow = _safe_get_mapping(external_parameters, "workflow")
    source = _safe_get_mapping(external_parameters, "source")

    result["repository"] = (
        _safe_get_string(workflow, "repository")
        or _safe_get_string(source, "repository")
    )
    result["workflow_path"] = _safe_get_string(workflow, "path")

    run_details = _safe_get_mapping(predicate, "runDetails")
    builder = _safe_get_mapping(run_details, "builder")
    # Older provenance layouts sometimes carry builder directly at predicate
    # level; retain that fallback without guessing a value.
    result["builder_id"] = (
        _safe_get_string(builder, "id")
        or _safe_get_string(_safe_get_mapping(predicate, "builder"), "id")
    )

    resolved_dependencies = build_definition.get("resolvedDependencies")
    if isinstance(resolved_dependencies, list):
        for dependency in resolved_dependencies:
            digest = _safe_get_mapping(dependency, "digest")
            commit = (
                _safe_get_string(digest, "gitCommit")
                or _safe_get_string(digest, "sha1")
                or _safe_get_string(digest, "sha256")
            )
            if commit:
                result["commit"] = commit
                break

    return result
