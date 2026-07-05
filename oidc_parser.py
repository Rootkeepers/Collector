"""Utilities for extracting Fulcio/GitHub OIDC claims from verification material."""

from __future__ import annotations

import base64
import binascii
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID, ObjectIdentifier


class OIDCParseError(Exception):
    """Raised when Fulcio certificate material cannot be parsed safely."""


FULCIO_OIDC_ISSUER_OID = ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
FULCIO_GITHUB_OIDS: dict[str, str] = {
    "1.3.6.1.4.1.57264.1.2": "github_workflow_trigger",
    "1.3.6.1.4.1.57264.1.3": "github_workflow_sha",
    "1.3.6.1.4.1.57264.1.4": "github_workflow_name",
    "1.3.6.1.4.1.57264.1.5": "github_workflow_repository",
    "1.3.6.1.4.1.57264.1.6": "github_workflow_ref",
    "1.3.6.1.4.1.57264.1.9": "build_signer_uri",
    "1.3.6.1.4.1.57264.1.10": "build_signer_digest",
    "1.3.6.1.4.1.57264.1.11": "runner_environment",
    "1.3.6.1.4.1.57264.1.12": "source_repository_uri",
    "1.3.6.1.4.1.57264.1.13": "source_repository_digest",
    "1.3.6.1.4.1.57264.1.14": "source_repository_ref",
}


def parse_fulcio_oidc_info(verification_material: dict[str, Any]) -> dict[str, Any]:
    """Extract OIDC identity fields from a Sigstore Fulcio certificate.

    Args:
        verification_material: The ``verificationMaterial`` object from a
            Sigstore/npm attestation bundle.

    Returns:
        A dictionary containing ``issuer``, ``subject``, ``subject_repo``,
        ``subject_workflow``, ``san_uris``, ``san_emails``, and recognized
        Fulcio GitHub custom OID extension values.

    Raises:
        OIDCParseError: If certificate material is missing or malformed.
    """
    certificate = _load_leaf_certificate(verification_material)
    issuer = _extract_oidc_issuer(certificate)
    san_uris, san_emails = _extract_subject_alt_names(certificate)
    common_name = _first_common_name(certificate)

    subject = san_uris[0] if san_uris else san_emails[0] if san_emails else common_name
    github_extensions = _extract_fulcio_github_extensions(certificate)

    subject_repo = _extract_repo_from_subject(subject) or _normalize_repo(
        github_extensions.get("github_workflow_repository", "")
        or github_extensions.get("source_repository_uri", "")
    )
    subject_workflow = _extract_workflow_from_subject(subject)
    if not subject_workflow:
        subject_workflow = _extract_workflow_from_signer_uri(
            github_extensions.get("build_signer_uri", "")
        )

    return {
        "issuer": issuer,
        "subject": subject,
        "subject_repo": subject_repo,
        "subject_workflow": subject_workflow,
        "san_uris": san_uris,
        "san_emails": san_emails,
        **github_extensions,
    }


def _load_leaf_certificate(verification_material: dict[str, Any]) -> x509.Certificate:
    if not isinstance(verification_material, dict):
        raise OIDCParseError("verificationMaterial must be a dictionary")

    certificate_bytes = _extract_leaf_certificate_bytes(verification_material)
    try:
        if b"-----BEGIN CERTIFICATE-----" in certificate_bytes:
            return x509.load_pem_x509_certificate(certificate_bytes)
        return x509.load_der_x509_certificate(certificate_bytes)
    except ValueError as error:
        raise OIDCParseError(f"Unable to parse Fulcio certificate: {error}") from error


def _extract_leaf_certificate_bytes(verification_material: dict[str, Any]) -> bytes:
    chain = verification_material.get("x509CertificateChain")
    if isinstance(chain, list) and chain:
        return _certificate_entry_to_bytes(chain[0])

    if isinstance(chain, str):
        return _certificate_entry_to_bytes(chain)

    if isinstance(chain, dict):
        certificates = chain.get("certificates")
        if isinstance(certificates, list) and certificates:
            return _certificate_entry_to_bytes(certificates[0])

    certificate = verification_material.get("certificate")
    if certificate is not None:
        return _certificate_entry_to_bytes(certificate)

    raise OIDCParseError("verificationMaterial does not contain an x509 certificate")


def _certificate_entry_to_bytes(entry: Any) -> bytes:
    if isinstance(entry, str):
        return _decode_certificate_string(entry)

    if not isinstance(entry, dict):
        raise OIDCParseError("certificate entry must be a dictionary or PEM string")

    for key in ("pem", "cert", "certificate", "rawBytes"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            return _decode_certificate_string(value)

    raise OIDCParseError("certificate entry does not contain PEM or rawBytes data")


def _decode_certificate_string(value: str) -> bytes:
    stripped = value.strip()
    if "-----BEGIN CERTIFICATE-----" in stripped:
        return stripped.encode("utf-8")

    try:
        return base64.b64decode(stripped, validate=True)
    except binascii.Error as error:
        raise OIDCParseError(f"certificate is neither PEM nor valid Base64 DER: {error}") from error


def _extract_oidc_issuer(certificate: x509.Certificate) -> str:
    value = _get_unrecognized_extension(certificate, FULCIO_OIDC_ISSUER_OID)
    if value:
        return value

    raise OIDCParseError("Fulcio OIDC issuer extension is missing")


def _extract_subject_alt_names(certificate: x509.Certificate) -> tuple[list[str], list[str]]:
    try:
        san = certificate.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value
    except x509.ExtensionNotFound:
        return [], []

    uris = [str(uri) for uri in san.get_values_for_type(x509.UniformResourceIdentifier)]
    emails = [str(email) for email in san.get_values_for_type(x509.RFC822Name)]
    return uris, emails


def _first_common_name(certificate: x509.Certificate) -> str:
    attributes = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not attributes:
        return ""
    return str(attributes[0].value)


def _extract_fulcio_github_extensions(certificate: x509.Certificate) -> dict[str, str]:
    result: dict[str, str] = {}
    for oid_text, field_name in FULCIO_GITHUB_OIDS.items():
        value = _get_unrecognized_extension(certificate, ObjectIdentifier(oid_text))
        if value:
            result[field_name] = value
    return result


def _get_unrecognized_extension(
    certificate: x509.Certificate, oid: ObjectIdentifier
) -> str:
    try:
        extension = certificate.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return ""

    if isinstance(extension, x509.UnrecognizedExtension):
        return _decode_der_string(extension.value)

    return str(extension)


def _decode_der_string(value: bytes) -> str:
    """Decode the simple ASN.1 string wrappers Fulcio uses for custom OIDs."""
    if len(value) >= 2 and value[0] in {0x0C, 0x16, 0x13}:
        length = value[1]
        offset = 2
        if length & 0x80:
            length_size = length & 0x7F
            if len(value) < 2 + length_size:
                return value.hex()
            length = int.from_bytes(value[2 : 2 + length_size], "big")
            offset = 2 + length_size
        payload = value[offset : offset + length]
    else:
        payload = value

    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex()


def _extract_repo_from_subject(subject: str) -> str:
    if not subject.startswith("repo:"):
        return ""

    remainder = subject.removeprefix("repo:")
    parts = remainder.split(":")
    if not parts or "/" not in parts[0]:
        return ""
    return parts[0].lower()


def _extract_workflow_from_subject(subject: str) -> str:
    marker = ":workflow:"
    if marker not in subject:
        return ""
    workflow = subject.split(marker, 1)[1].split(":", 1)[0]
    return workflow.strip()


def _extract_workflow_from_signer_uri(value: str) -> str:
    marker = "/.github/workflows/"
    if marker not in value:
        return ""

    path = ".github/workflows/" + value.split(marker, 1)[1]
    return path.split("@", 1)[0].strip()


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


__all__ = ["OIDCParseError", "parse_fulcio_oidc_info"]
