"""Utilities for extracting Rekor transparency log metadata."""

from __future__ import annotations

from typing import Any


class RekorParseError(Exception):
    """Raised when Rekor transparency log material is malformed."""


def parse_rekor_log_info(verification_material: dict[str, Any]) -> dict[str, int] | None:
    """Extract the first Rekor transparency log entry from verification material.

    Args:
        verification_material: The ``verificationMaterial`` object from a
            Sigstore/npm attestation bundle.

    Returns:
        ``{"logIndex": int, "integratedTime": int}`` for the first entry, or
        ``None`` when the bundle has no transparency log entries.

    Raises:
        RekorParseError: If ``tlogEntries`` exists but has an unexpected shape
            or required fields cannot be converted to integers.
    """
    if not isinstance(verification_material, dict):
        raise RekorParseError("verificationMaterial must be a dictionary")

    entries = verification_material.get("tlogEntries", [])
    if entries in (None, []):
        return None

    if not isinstance(entries, list):
        raise RekorParseError("verificationMaterial.tlogEntries must be a list")

    first_entry = entries[0]
    if not isinstance(first_entry, dict):
        raise RekorParseError("tlogEntries[0] must be a dictionary")

    try:
        return {
            "logIndex": _to_int(first_entry["logIndex"], "logIndex"),
            "integratedTime": _to_int(
                first_entry["integratedTime"], "integratedTime"
            ),
        }
    except KeyError as error:
        raise RekorParseError(f"Missing required Rekor field: {error}") from error


def _to_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool):
        raise RekorParseError(f"Rekor field {field_name} must be an integer")

    try:
        return int(value)
    except (TypeError, ValueError) as error:
        raise RekorParseError(
            f"Rekor field {field_name} must be an integer-like value"
        ) from error


__all__ = ["RekorParseError", "parse_rekor_log_info"]
