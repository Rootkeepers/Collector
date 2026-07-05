"""Integration tests for Track C hardening fixes."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from cross_validator import validate_oidc_matches_predicate
from main import write_json
from oidc_parser import OIDCParseError, _extract_leaf_certificate_bytes
from schema_mapper import build_error_schema


PEM_CERTIFICATE = """-----BEGIN CERTIFICATE-----
MIIBlTCCATugAwIBAgIUPc6Nmw7IlY3Uw7uzhrKwJfFWZ7QwCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHVGVzdCBDQTAeFw0yNjAxMDEwMDAwMDBaFw0yNzAxMDEwMDAw
MDBaMBUxEzARBgNVBAMMClRlc3QgTGVhZjBZMBMGByqGSM49AgEGCCqGSM49AwEH
A0IABFJr3xWgNzuxZqBfQVDuZtDk6DJ5PLF22bHTYxUj24aX67h6tJdX84oXnqGp
j4MWW2VJqV0JzVdjq2m1pcuxU2CjUzBRMB0GA1UdDgQWBBSIT2PLTfgH9c2lGrTv
8AoHLQF5IjAfBgNVHSMEGDAWgBSIT2PLTfgH9c2lGrTv8AoHLQF5IjAPBgNVHRMB
Af8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQDcodL5A9ITJMj/61F7NydlT4W4
3NzTUV4tC9TQnR1dzgIgRSR6jI7EJHU8Y6HUM5Y1OOWE3HZVtCdW6c0yoQTg5kI=
-----END CERTIFICATE-----"""


def test_cross_validator_fails_when_predicate_workflow_is_missing() -> None:
    result = validate_oidc_matches_predicate(
        {
            "repository": "https://github.com/example/project",
            "workflow_path": "",
        },
        {
            "subject_repo": "example/project",
            "subject_workflow": ".github/workflows/release.yml",
        },
    )

    assert result["status"] == "FAIL"
    assert result["passed"] is False
    assert any(
        mismatch["field"] == "workflow_path"
        and mismatch["message"]
        == "Workflow identity is missing from SLSA predicate or Fulcio OIDC claims"
        for mismatch in result["mismatches"]
    )


def test_cross_validator_fails_when_oidc_workflow_is_missing() -> None:
    result = validate_oidc_matches_predicate(
        {
            "repository": "https://github.com/example/project",
            "workflow_path": ".github/workflows/release.yml",
        },
        {
            "subject_repo": "example/project",
            "subject_workflow": "",
        },
    )

    assert result["status"] == "FAIL"
    assert result["passed"] is False
    assert any(
        mismatch["field"] == "workflow_path"
        and mismatch["message"]
        == "Workflow identity is missing from SLSA predicate or Fulcio OIDC claims"
        for mismatch in result["mismatches"]
    )


def test_build_error_schema_contains_pass_schema_dummy_keys() -> None:
    document = build_error_schema(
        package_name="missing-package",
        package_version="0.0.1",
        attestation_url="https://registry.npmjs.org/-/npm/v1/attestations/missing-package@0.0.1",
        error_type="CollectorError",
        message="not found",
    )

    assert document["schema_version"] == "srp.track-c.v1"
    assert document["validation"]["status"] == "ERROR"
    assert document["slsa_predicate"] == {
        "repository": "",
        "commit": "",
        "workflow_path": "",
    }
    assert document["fulcio_oidc"] == {
        "issuer": "",
        "subject": "",
        "subject_repo": "",
        "subject_workflow": "",
        "san_uris": [],
        "san_emails": [],
        "github_extensions": {},
    }
    assert document["rekor"] == {
        "present": False,
        "logIndex": None,
        "integratedTime": None,
    }


def test_write_json_falls_back_to_stdout_on_output_file_oserror(capsys: pytest.CaptureFixture[str]) -> None:
    document = {"schema_version": "srp.track-c.v1", "validation": {"status": "PASS"}}

    with patch.object(Path, "write_text", side_effect=OSError("permission denied")):
        write_json(document, Path("blocked.json"))

    captured = capsys.readouterr()

    assert "warning: failed to write JSON to blocked.json" in captured.err
    assert "permission denied" in captured.err
    assert '"schema_version": "srp.track-c.v1"' in captured.out
    assert '"status": "PASS"' in captured.out


def test_extract_leaf_certificate_bytes_accepts_pem_string_chain() -> None:
    verification_material = {"x509CertificateChain": PEM_CERTIFICATE}

    try:
        certificate_bytes = _extract_leaf_certificate_bytes(verification_material)
    except OIDCParseError as error:
        pytest.fail(f"PEM string chain should not raise OIDCParseError: {error}")

    assert certificate_bytes == PEM_CERTIFICATE.encode("utf-8")


def test_extract_leaf_certificate_bytes_accepts_pem_list_chain() -> None:
    verification_material = {"x509CertificateChain": [PEM_CERTIFICATE]}

    try:
        certificate_bytes = _extract_leaf_certificate_bytes(verification_material)
    except OIDCParseError as error:
        pytest.fail(f"PEM list chain should not raise OIDCParseError: {error}")

    assert certificate_bytes == PEM_CERTIFICATE.encode("utf-8")
