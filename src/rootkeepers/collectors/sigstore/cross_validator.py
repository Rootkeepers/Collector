"""Cross-validation between SLSA predicate fields and Fulcio OIDC claims."""

from __future__ import annotations

from typing import Any


class CrossValidationError(Exception):
    """Raised when validator inputs are malformed."""


def validate_oidc_matches_predicate(
    predicate_info: dict[str, Any], oidc_info: dict[str, Any]
) -> dict[str, Any]:
    """Validate that SLSA predicate lineage matches Fulcio OIDC identity.

    Args:
        predicate_info: Output from ``parse_slsa_predicate``. Expected keys are
            ``repository`` and ``workflow_path``.
        oidc_info: Output from ``parse_fulcio_oidc_info``. Expected keys are
            ``subject_repo`` and optionally ``subject_workflow``.

    Returns:
        A result dictionary with ``status`` set to ``"PASS"`` or ``"FAIL"``,
        ``passed`` as a boolean, and a list of mismatch details.

    Raises:
        CrossValidationError: If either input is not a dictionary.
    """
    if not isinstance(predicate_info, dict):
        raise CrossValidationError("predicate_info must be a dictionary")
    if not isinstance(oidc_info, dict):
        raise CrossValidationError("oidc_info must be a dictionary")

    predicate_repo = _normalize_repo(_string_value(predicate_info, "repository"))
    oidc_repo = _normalize_repo(_string_value(oidc_info, "subject_repo"))

    predicate_workflow = _normalize_workflow_path(
        _string_value(predicate_info, "workflow_path")
    )
    oidc_workflow = _normalize_workflow_path(
        _string_value(oidc_info, "subject_workflow")
    )

    mismatches: list[dict[str, str]] = []
    _compare_required(
        mismatches,
        "repository",
        predicate_repo,
        oidc_repo,
        "SLSA predicate repository does not match Fulcio OIDC subject repository",
    )

    if not predicate_workflow or not oidc_workflow:
        mismatches.append(
            {
                "rule": "OIDC_MISMATCH",
                "field": "workflow_path",
                "predicate": predicate_workflow,
                "oidc": oidc_workflow,
                "message": "Workflow identity is missing from SLSA predicate or Fulcio OIDC claims",
            }
        )
    elif predicate_workflow != oidc_workflow:
        mismatches.append(
            {
                "rule": "OIDC_MISMATCH",
                "field": "workflow_path",
                "predicate": predicate_workflow,
                "oidc": oidc_workflow,
                "message": "SLSA predicate workflow path does not match Fulcio OIDC workflow",
            }
        )

    passed = not mismatches
    return {
        "status": "PASS" if passed else "FAIL",
        "passed": passed,
        "rule": "OIDC_MISMATCH",
        "predicate": {
            "repository": predicate_repo,
            "workflow_path": predicate_workflow,
        },
        "oidc": {
            "subject_repo": oidc_repo,
            "subject_workflow": oidc_workflow,
            "issuer": _string_value(oidc_info, "issuer"),
            "subject": _string_value(oidc_info, "subject"),
        },
        "mismatches": mismatches,
    }


def is_oidc_match(predicate_info: dict[str, Any], oidc_info: dict[str, Any]) -> bool:
    """Return only the boolean pass/fail result for OIDC cross-validation."""
    return bool(validate_oidc_matches_predicate(predicate_info, oidc_info)["passed"])


def _compare_required(
    mismatches: list[dict[str, str]],
    field: str,
    predicate_value: str,
    oidc_value: str,
    message: str,
) -> None:
    if predicate_value and oidc_value and predicate_value == oidc_value:
        return

    mismatches.append(
        {
            "rule": "OIDC_MISMATCH",
            "field": field,
            "predicate": predicate_value,
            "oidc": oidc_value,
            "message": message,
        }
    )


def _string_value(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key, "")
    return value if isinstance(value, str) else ""


def _normalize_repo(value: str) -> str:
    normalized = value.strip()
    if normalized.startswith("git+"):
        normalized = normalized.removeprefix("git+")
    for prefix in ("https://github.com/", "http://github.com/", "github.com/"):
        if normalized.startswith(prefix):
            normalized = normalized.removeprefix(prefix)
            break
    normalized = normalized.removesuffix(".git").strip("/")
    return normalized.lower()


def _normalize_workflow_path(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        return ""

    marker = ".github/workflows/"
    if marker in normalized:
        normalized = marker + normalized.split(marker, 1)[1]

    normalized = normalized.split("@", 1)[0]
    return normalized.replace("\\", "/").lstrip("/").lower()


__all__ = [
    "CrossValidationError",
    "is_oidc_match",
    "validate_oidc_matches_predicate",
]
