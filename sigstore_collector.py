"""Extract TrustGate supply-chain lineage from Sigstore DSSE bundles.

This module parses metadata only.  A ``PASS`` result means the required
lineage fields and transparency-log metadata were present and internally
consistent; it does not replace cryptographic signature, certificate-chain,
or Rekor inclusion-proof verification.
"""

from __future__ import annotations

import base64
import binascii
import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography import x509
from cryptography.x509 import Certificate


_OID_ISSUER = "1.3.6.1.4.1.57264.1.1"
_OID_TRIGGER_SHA = "1.3.6.1.4.1.57264.1.3"
_OID_REPOSITORY = "1.3.6.1.4.1.57264.1.5"
_SIGSTORE_OIDS = {
    _OID_ISSUER,
    _OID_TRIGGER_SHA,
    _OID_REPOSITORY,
}


class BundleParseError(ValueError):
    """Raised when required Sigstore bundle data cannot be parsed."""


def _empty_result() -> dict[str, Any]:
    """Return a fresh result matching the TrustGate output schema."""
    return {
        "source": "sigstore",
        "status": "UNVERIFIABLE",
        "oidc": {
            "issuer": "",
            "subject": "",
            "repository": "",
            "workflow": "",
        },
        "builder": {
            "id": "",
            "workflow_path": "",
        },
        "verified_commit": "",
    }


def _as_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BundleParseError(f"{field_name} must be a JSON object")
    return value


def _decode_payload(bundle: Mapping[str, Any]) -> Mapping[str, Any]:
    """Base64-decode and deserialize the DSSE payload."""
    envelope = _as_mapping(bundle.get("dsseEnvelope"), "dsseEnvelope")
    encoded = envelope.get("payload")
    if not isinstance(encoded, str) or not encoded:
        raise BundleParseError("dsseEnvelope.payload is missing")

    try:
        raw_payload = base64.b64decode(encoded, validate=True)
        decoded = json.loads(raw_payload.decode("utf-8"))
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BundleParseError("invalid DSSE payload") from exc

    statement = _as_mapping(decoded, "decoded DSSE payload")
    predicate = statement.get("predicate", statement)
    return _as_mapping(predicate, "SLSA predicate")


def _load_certificate(bundle: Mapping[str, Any]) -> Certificate:
    """Load the first Fulcio certificate from the bundle as an X.509 object."""
    verification = _as_mapping(
        bundle.get("verificationMaterial"), "verificationMaterial"
    )
    chain = _as_mapping(
        verification.get("x509CertificateChain"), "x509CertificateChain"
    )
    certificates = chain.get("certificates")
    if not isinstance(certificates, Sequence) or isinstance(certificates, (str, bytes)):
        raise BundleParseError("certificate chain is missing")
    if not certificates:
        raise BundleParseError("certificate chain is empty")

    first = certificates[0]
    if isinstance(first, Mapping):
        encoded = first.get("rawBytes")
    else:
        encoded = first
    if not isinstance(encoded, str) or not encoded:
        raise BundleParseError("first certificate is invalid")

    try:
        certificate_bytes = base64.b64decode(encoded, validate=True)
        if certificate_bytes.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
            return x509.load_pem_x509_certificate(certificate_bytes)
        return x509.load_der_x509_certificate(certificate_bytes)
    except (binascii.Error, ValueError) as exc:
        raise BundleParseError("unable to decode Fulcio certificate") from exc


def _decode_der_length(data: bytes, offset: int) -> tuple[int, int]:
    """Decode a DER length and return ``(length, next_offset)``."""
    if offset >= len(data):
        raise ValueError("missing DER length")
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    length_octets = first & 0x7F
    if length_octets == 0 or length_octets > 4:
        raise ValueError("unsupported DER length")
    end = offset + 1 + length_octets
    if end > len(data):
        raise ValueError("truncated DER length")
    return int.from_bytes(data[offset + 1 : end], "big"), end


def _decode_extension_value(extension: x509.Extension[Any]) -> str:
    """Decode a Fulcio custom extension, including DER string wrappers."""
    value = extension.value
    raw = value.value if isinstance(value, x509.UnrecognizedExtension) else None
    if not isinstance(raw, bytes):
        raw = getattr(value, "value", b"")
    if isinstance(raw, str):
        return raw.strip()
    if not isinstance(raw, bytes) or not raw:
        return ""

    # Fulcio custom claims are commonly encoded as DER UTF8String or IA5String.
    if raw[0] in {0x0C, 0x13, 0x16}:
        try:
            length, start = _decode_der_length(raw, 1)
            end = start + length
            if end == len(raw):
                raw = raw[start:end]
        except ValueError:
            pass
    return raw.decode("utf-8", errors="replace").strip().strip("\x00")


def _certificate_claims(certificate: Certificate) -> dict[str, str]:
    """Return the requested custom Sigstore extension values by OID."""
    claims: dict[str, str] = {}
    for extension in certificate.extensions:
        oid = extension.oid.dotted_string
        if oid in _SIGSTORE_OIDS:
            claims[oid] = _decode_extension_value(extension)
    return claims


def _certificate_san_uri(certificate: Certificate) -> str:
    """Return the first URI identity from the certificate's SAN extension."""
    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return ""

    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    return uris[0].strip() if uris else ""


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _extract_repository(external_parameters: Mapping[str, Any]) -> str:
    source = external_parameters.get("source")
    if isinstance(source, str):
        return source.strip()
    if isinstance(source, Mapping):
        for key in ("repository", "uri", "url"):
            candidate = _string(source.get(key))
            if candidate:
                return candidate
    return ""


def _extract_commit(resolved_dependencies: Any) -> str:
    if not isinstance(resolved_dependencies, Sequence) or isinstance(
        resolved_dependencies, (str, bytes)
    ):
        return ""
    for dependency in resolved_dependencies:
        if not isinstance(dependency, Mapping):
            continue
        digest = dependency.get("digest")
        if isinstance(digest, Mapping):
            for key in ("gitCommit", "sha1", "sha256"):
                candidate = _string(digest.get(key))
                if candidate:
                    return candidate
    return ""


def _extract_workflow_path(internal_parameters: Mapping[str, Any]) -> str:
    for key in ("workflow", "workflowPath", "workflow_path"):
        value = internal_parameters.get(key)
        if isinstance(value, Mapping):
            value = value.get("path")
        candidate = _string(value)
        if candidate:
            return candidate
    return ""


def _extract_tlog_metadata(bundle: Mapping[str, Any]) -> tuple[Any, Any]:
    """Extract required Rekor metadata from the first transparency-log entry."""
    verification = _as_mapping(
        bundle.get("verificationMaterial"), "verificationMaterial"
    )
    entries = verification.get("tlogEntries")
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        raise BundleParseError("tlogEntries is missing")
    if not entries or not isinstance(entries[0], Mapping):
        raise BundleParseError("tlogEntries is empty or invalid")
    log_index = entries[0].get("logIndex")
    integrated_time = entries[0].get("integratedTime")
    if log_index is None or integrated_time is None:
        raise BundleParseError("Rekor logIndex or integratedTime is missing")
    return log_index, integrated_time


def parse_sigstore_bundle(bundle_filepath: str) -> dict[str, Any]:
    """Parse a Sigstore bundle into TrustGate's lineage output schema.

    Any malformed bundle or missing critical lineage field produces a stable
    ``UNVERIFIABLE`` result rather than propagating parsing exceptions.

    Args:
        bundle_filepath: Path to an npm ``attestation.json`` Sigstore bundle.

    Returns:
        A dictionary matching the TrustGate Sigstore collector schema exactly.
    """
    result = _empty_result()

    try:
        with Path(bundle_filepath).open("r", encoding="utf-8") as bundle_file:
            bundle = _as_mapping(json.load(bundle_file), "bundle")

        predicate = _decode_payload(bundle)
        build_definition = _as_mapping(
            predicate.get("buildDefinition"), "predicate.buildDefinition"
        )
        external_parameters = _as_mapping(
            build_definition.get("externalParameters", {}), "externalParameters"
        )
        internal_parameters = _as_mapping(
            build_definition.get("internalParameters", {}), "internalParameters"
        )
        run_details = predicate.get("runDetails", {})
        run_details = _as_mapping(run_details, "predicate.runDetails")
        builder = run_details.get("builder", predicate.get("builder", {}))
        builder = _as_mapping(builder, "predicate builder")

        predicate_repository = _extract_repository(external_parameters)
        predicate_commit = _extract_commit(
            build_definition.get("resolvedDependencies")
        )
        certificate = _load_certificate(bundle)
        certificate_claims = _certificate_claims(certificate)
        certificate_subject = _certificate_san_uri(certificate)
        _extract_tlog_metadata(bundle)

        certificate_repository = certificate_claims.get(_OID_REPOSITORY, "")
        certificate_commit = certificate_claims.get(_OID_TRIGGER_SHA, "")
        repository = certificate_repository or predicate_repository
        commit = certificate_commit or predicate_commit

        result["oidc"] = {
            "issuer": certificate_claims.get(_OID_ISSUER, ""),
            "subject": certificate_subject,
            "repository": repository,
            "workflow": certificate_commit,
        }
        result["builder"] = {
            "id": _string(builder.get("id")),
            "workflow_path": _extract_workflow_path(internal_parameters),
        }
        result["verified_commit"] = commit

        required_output = (
            result["oidc"]["issuer"],
            result["oidc"]["subject"],
            result["oidc"]["repository"],
            result["oidc"]["workflow"],
            result["builder"]["id"],
            result["verified_commit"],
        )
        required_evidence = (
            predicate_repository,
            predicate_commit,
            certificate_repository,
            certificate_commit,
        )
        repositories_match = not (
            predicate_repository
            and certificate_repository
            and predicate_repository != certificate_repository
        )
        commits_match = not (
            predicate_commit
            and certificate_commit
            and predicate_commit.lower() != certificate_commit.lower()
        )
        if (
            all(required_output)
            and all(required_evidence)
            and repositories_match
            and commits_match
        ):
            result["status"] = "PASS"
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        # Preserve any safely extracted data while guaranteeing the schema and
        # conservative status expected by downstream TrustGate processing.
        result["status"] = "UNVERIFIABLE"

    return result


__all__ = ["parse_sigstore_bundle"]
