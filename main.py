"""CLI entry point for the npm Sigstore/Rekor release lineage collector."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

from bundle_parser import BundleParseError, extract_predicate_from_dsse
from cross_validator import CrossValidationError, validate_oidc_matches_predicate
from oidc_parser import OIDCParseError, parse_fulcio_oidc_info
from predicate_parser import parse_slsa_predicate
from rekor_parser import RekorParseError, parse_rekor_log_info
from schema_mapper import (
    SchemaMappingError,
    build_error_schema,
    build_release_lineage_schema,
)


NPM_ATTESTATIONS_BASE_URL = "https://registry.npmjs.org/-/npm/v1/attestations"
DEFAULT_TIMEOUT_SECONDS = 15


class CollectorError(Exception):
    """Raised when the collector cannot produce a validated lineage document."""


def collect_release_lineage(
    package_name: str,
    package_version: str,
    *,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Fetch npm attestations, parse Track C signals, and return unified JSON."""
    attestation_url = build_attestation_url(package_name, package_version)
    response_data = fetch_attestations(attestation_url, timeout=timeout)
    attestations = response_data.get("attestations", [])

    if not isinstance(attestations, list) or not attestations:
        raise CollectorError("npm attestation response does not contain attestations")

    parse_errors: list[str] = []
    for index, attestation in enumerate(attestations, start=1):
        if not isinstance(attestation, dict):
            parse_errors.append(f"attestation {index}: expected object")
            continue

        bundle = attestation.get("bundle", {})
        if not isinstance(bundle, dict):
            parse_errors.append(f"attestation {index}: bundle is missing or malformed")
            continue

        try:
            predicate = extract_predicate_from_dsse(bundle)
        except BundleParseError as error:
            parse_errors.append(f"attestation {index}: DSSE parse skipped: {error}")
            continue

        if "buildDefinition" not in predicate:
            parse_errors.append(f"attestation {index}: skipped non-SLSA provenance")
            continue

        try:
            predicate_info = parse_slsa_predicate(predicate)
            verification_material = bundle.get("verificationMaterial", {})
            oidc_info = parse_fulcio_oidc_info(verification_material)
            rekor_info = parse_rekor_log_info(verification_material)
            validation_result = validate_oidc_matches_predicate(
                predicate_info, oidc_info
            )
            return build_release_lineage_schema(
                package_name=package_name,
                package_version=package_version,
                attestation_url=attestation_url,
                attestation_index=index,
                predicate_info=predicate_info,
                oidc_info=oidc_info,
                rekor_info=rekor_info,
                validation_result=validation_result,
            )
        except (
            OIDCParseError,
            RekorParseError,
            CrossValidationError,
            SchemaMappingError,
        ) as error:
            parse_errors.append(f"attestation {index}: {error}")
            continue

    detail = "; ".join(parse_errors[-5:]) if parse_errors else "no parse details"
    raise CollectorError(f"no usable SLSA provenance attestation found ({detail})")


def build_attestation_url(package_name: str, package_version: str) -> str:
    """Build the npm attestation API URL for regular and scoped packages."""
    package_spec = f"{package_name}@{package_version}"
    encoded_spec = quote(package_spec, safe="@")
    return f"{NPM_ATTESTATIONS_BASE_URL}/{encoded_spec}"


def fetch_attestations(url: str, *, timeout: int) -> dict[str, Any]:
    """Fetch and decode the npm attestation API response."""
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        data = response.json()
    except requests.RequestException as error:
        raise CollectorError(f"failed to fetch npm attestations: {error}") from error
    except json.JSONDecodeError as error:
        raise CollectorError(f"npm attestation response is not valid JSON: {error}") from error

    if not isinstance(data, dict):
        raise CollectorError("npm attestation response must be a JSON object")
    return data


def write_json(document: dict[str, Any], output_path: Path | None) -> None:
    """Write JSON either to stdout or to a file."""
    rendered = json.dumps(document, indent=2, ensure_ascii=False)
    if output_path is None:
        print(rendered)
        return

    output_path.write_text(rendered + "\n", encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect and validate npm Sigstore/Rekor release lineage."
    )
    parser.add_argument("package", help="npm package name, e.g. vite or @scope/name")
    parser.add_argument("version", help="npm package version, e.g. 5.2.0")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="write final JSON to this file instead of stdout",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"npm registry request timeout in seconds (default: {DEFAULT_TIMEOUT_SECONDS})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    attestation_url = build_attestation_url(args.package, args.version)

    try:
        document = collect_release_lineage(
            args.package,
            args.version,
            timeout=args.timeout,
        )
        write_json(document, args.output)
    except (CollectorError, SchemaMappingError) as error:
        error_document = build_error_schema(
            package_name=args.package,
            package_version=args.version,
            attestation_url=attestation_url,
            error_type=error.__class__.__name__,
            message=str(error),
        )
        write_json(error_document, args.output)
        print(f"collector error: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
