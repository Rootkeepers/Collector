"""Map collector outputs into one stable release-lineage JSON document."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


SCHEMA_VERSION = "srp.track-c.v1"


class SchemaMappingError(Exception):
    """Raised when parser outputs cannot be mapped into the unified schema."""


def build_release_lineage_schema(
    *,
    package_name: str,
    package_version: str,
    attestation_url: str,
    attestation_index: int,
    predicate_info: dict[str, Any],
    oidc_info: dict[str, Any],
    rekor_info: dict[str, Any] | None,
    validation_result: dict[str, Any],
) -> dict[str, Any]:
    """Aggregate parser and validator outputs into one SRP-compliant schema.

    The mapper intentionally performs no network calls, parsing, or validation.
    Its single responsibility is to normalize already-computed Track C outputs
    into a stable JSON contract that can be consumed by the final Consumer Gate.
    """
    _require_string(package_name, "package_name")
    _require_string(package_version, "package_version")
    _require_mapping(predicate_info, "predicate_info")
    _require_mapping(oidc_info, "oidc_info")
    _require_mapping(validation_result, "validation_result")
    if rekor_info is not None:
        _require_mapping(rekor_info, "rekor_info")

    passed = bool(validation_result.get("passed", False))
    validation_status = "PASS" if passed else "FAIL"

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package": {
            "ecosystem": "npm",
            "name": package_name,
            "version": package_version,
            "purl": f"pkg:npm/{package_name}@{package_version}",
        },
        "attestation": {
            "source": "npm-registry",
            "url": attestation_url,
            "selected_index": attestation_index,
            "type": "slsa-provenance",
        },
        "slsa_predicate": {
            "repository": _string_value(predicate_info, "repository"),
            "commit": _string_value(predicate_info, "commit"),
            "workflow_path": _string_value(predicate_info, "workflow_path"),
        },
        "fulcio_oidc": {
            "issuer": _string_value(oidc_info, "issuer"),
            "subject": _string_value(oidc_info, "subject"),
            "subject_repo": _string_value(oidc_info, "subject_repo"),
            "subject_workflow": _string_value(oidc_info, "subject_workflow"),
            "san_uris": _list_value(oidc_info, "san_uris"),
            "san_emails": _list_value(oidc_info, "san_emails"),
            "github_extensions": _github_extensions(oidc_info),
        },
        "rekor": {
            "present": rekor_info is not None,
            "logIndex": _optional_int_value(rekor_info, "logIndex"),
            "integratedTime": _optional_int_value(rekor_info, "integratedTime"),
        },
        "validation": {
            "status": validation_status,
            "passed": passed,
            "rules": [
                {
                    "id": "5.4",
                    "name": "OIDC_MISMATCH",
                    "status": validation_status,
                    "mismatches": validation_result.get("mismatches", []),
                }
            ],
            "raw": validation_result,
        },
    }


def build_error_schema(
    *,
    package_name: str,
    package_version: str,
    attestation_url: str,
    error_type: str,
    message: str,
) -> dict[str, Any]:
    """Build a structured error document for failed collection attempts."""
    _require_string(package_name, "package_name")
    _require_string(package_version, "package_version")
    _require_string(error_type, "error_type")
    _require_string(message, "message")

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package": {
            "ecosystem": "npm",
            "name": package_name,
            "version": package_version,
            "purl": f"pkg:npm/{package_name}@{package_version}",
        },
        "attestation": {
            "source": "npm-registry",
            "url": attestation_url,
            "selected_index": None,
            "type": None,
        },
        "slsa_predicate": {
            "repository": "",
            "commit": "",
            "workflow_path": "",
        },
        "fulcio_oidc": {
            "issuer": "",
            "subject": "",
            "subject_repo": "",
            "subject_workflow": "",
            "san_uris": [],
            "san_emails": [],
            "github_extensions": {},
        },
        "rekor": {
            "present": False,
            "logIndex": None,
            "integratedTime": None,
        },
        "validation": {
            "status": "ERROR",
            "passed": False,
            "rules": [],
            "raw": {},
        },
        "error": {
            "type": error_type,
            "message": message,
        },
    }


def _github_extensions(oidc_info: dict[str, Any]) -> dict[str, Any]:
    excluded = {
        "issuer",
        "subject",
        "subject_repo",
        "subject_workflow",
        "san_uris",
        "san_emails",
    }
    return {
        key: value
        for key, value in oidc_info.items()
        if key not in excluded and _is_json_scalar_or_list(value)
    }


def _is_json_scalar_or_list(value: Any) -> bool:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return True
    if isinstance(value, list):
        return all(isinstance(item, (str, int, float, bool)) or item is None for item in value)
    return False


def _require_string(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value:
        raise SchemaMappingError(f"{field_name} must be a non-empty string")


def _require_mapping(value: Any, field_name: str) -> None:
    if not isinstance(value, dict):
        raise SchemaMappingError(f"{field_name} must be a dictionary")


def _string_value(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key, "")
    return value if isinstance(value, str) else ""


def _list_value(mapping: dict[str, Any], key: str) -> list[Any]:
    value = mapping.get(key, [])
    return value if isinstance(value, list) else []


def _optional_int_value(mapping: dict[str, Any] | None, key: str) -> int | None:
    if mapping is None:
        return None
    value = mapping.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise SchemaMappingError(f"{key} must be an integer-like value") from error


__all__ = [
    "SCHEMA_VERSION",
    "SchemaMappingError",
    "build_error_schema",
    "build_release_lineage_schema",
]
