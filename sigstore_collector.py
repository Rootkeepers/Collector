"""Extract TrustGate supply-chain lineage from Sigstore DSSE bundles.

The collector accepts both a standalone Sigstore bundle and the modern npm
attestations API response, which wraps one or more bundles in an
``attestations`` array.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import unquote, urlparse

from cryptography import x509
from cryptography.x509 import Certificate


_SLSA_PROVENANCE_PREFIX = "https://slsa.dev/provenance/"
_OID_ISSUER = "1.3.6.1.4.1.57264.1.1"
_OID_WORKFLOW_SHA = "1.3.6.1.4.1.57264.1.3"
_OID_REPOSITORY = "1.3.6.1.4.1.57264.1.5"
_SIGSTORE_OIDS = {_OID_ISSUER, _OID_WORKFLOW_SHA, _OID_REPOSITORY}


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
        "rekor_log_index": None,
    }


def _as_mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    """Return ``value`` as a mapping or raise a descriptive parse error."""
    if not isinstance(value, Mapping):
        raise BundleParseError(f"{field_name} must be a JSON object")
    return value


def _is_sequence(value: Any) -> bool:
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


def _string(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _select_bundle(document: Mapping[str, Any]) -> Mapping[str, Any]:
    """Select the SLSA provenance bundle from a supported npm document."""
    if isinstance(document.get("dsseEnvelope"), Mapping):
        return document

    direct_bundle = document.get("bundle")
    if isinstance(direct_bundle, Mapping) and isinstance(
        direct_bundle.get("dsseEnvelope"), Mapping
    ):
        return direct_bundle

    attestations = document.get("attestations")
    if not _is_sequence(attestations):
        raise BundleParseError("no Sigstore bundle or npm attestations found")

    fallback: Mapping[str, Any] | None = None
    for candidate in attestations:
        if not isinstance(candidate, Mapping):
            continue
        bundle = candidate.get("bundle")
        if not isinstance(bundle, Mapping) or not isinstance(
            bundle.get("dsseEnvelope"), Mapping
        ):
            continue
        if fallback is None:
            fallback = bundle
        predicate_type = _string(candidate.get("predicateType"))
        if predicate_type.startswith(_SLSA_PROVENANCE_PREFIX):
            return bundle

    if fallback is not None:
        return fallback
    raise BundleParseError("npm response contains no usable Sigstore bundle")


def _decode_payload(document: Mapping[str, Any]) -> Mapping[str, Any]:
    """Decode a DSSE payload and return its SLSA predicate.

    ``document`` may be a standalone bundle, an npm attestation item, or a
    modern npm response containing an ``attestations`` array.
    """
    bundle = _select_bundle(document)
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
    predicate = statement.get("predicate")
    if predicate is None:
        # Accommodate callers that provide an already-decoded predicate.
        predicate = statement
    return _as_mapping(predicate, "SLSA predicate")


def _certificate_bytes(certificate_value: Any) -> bytes:
    """Decode a certificate represented by a rawBytes object or Base64 text."""
    if isinstance(certificate_value, Mapping):
        encoded = certificate_value.get("rawBytes")
    else:
        encoded = certificate_value
    if not isinstance(encoded, str) or not encoded:
        raise BundleParseError("Fulcio certificate rawBytes is missing")
    try:
        return base64.b64decode(encoded, validate=True)
    except binascii.Error as exc:
        raise BundleParseError("Fulcio certificate is not valid Base64") from exc


def _load_certificate(document: Mapping[str, Any]) -> Certificate | None:
    """Load a Fulcio leaf certificate, or return ``None`` for key signing."""
    bundle = _select_bundle(document)
    verification = _as_mapping(
        bundle.get("verificationMaterial"), "verificationMaterial"
    )

    certificate_value = verification.get("certificate")
    if certificate_value is None:
        chain = verification.get("x509CertificateChain")
        if not isinstance(chain, Mapping):
            if isinstance(verification.get("publicKey"), Mapping):
                return None
            raise BundleParseError("Fulcio certificate is missing")
        certificates = chain.get("certificates")
        if not _is_sequence(certificates) or not certificates:
            raise BundleParseError("Fulcio certificate chain is empty")
        certificate_value = certificates[0]

    certificate_bytes = _certificate_bytes(certificate_value)
    try:
        if certificate_bytes.lstrip().startswith(b"-----BEGIN CERTIFICATE-----"):
            return x509.load_pem_x509_certificate(certificate_bytes)
        return x509.load_der_x509_certificate(certificate_bytes)
    except ValueError as exc:
        raise BundleParseError("unable to parse Fulcio certificate") from exc


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

    # New Fulcio OIDs use DER UTF8String; legacy OIDs may contain plain UTF-8.
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
    """Extract the requested custom Sigstore claims by OID."""
    claims: dict[str, str] = {}
    for extension in certificate.extensions:
        oid = extension.oid.dotted_string
        if oid in _SIGSTORE_OIDS:
            claims[oid] = _decode_extension_value(extension)
    return claims


def _certificate_san_uri(certificate: Certificate) -> str:
    """Return the first URI identity in the certificate SAN extension."""
    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value
    except x509.ExtensionNotFound:
        return ""
    uris = san.get_values_for_type(x509.UniformResourceIdentifier)
    return uris[0].strip() if uris else ""


def _normalize_repository(repository: str) -> str:
    """Normalize a GitHub repository reference to lowercase ``owner/repo``."""
    value = unquote(_string(repository)).replace("\\", "/")
    if not value:
        return ""

    if value.startswith("git+"):
        value = value[4:]
    scp_match = re.match(r"^(?:[^@/]+@)?github\.com:(.+)$", value, re.I)
    if scp_match:
        path = scp_match.group(1)
    else:
        parsed = urlparse(value)
        if parsed.hostname:
            if parsed.hostname.lower() not in {"github.com", "www.github.com"}:
                return ""
            path = parsed.path
        else:
            github_match = re.search(r"(?:^|/)github\.com/(.+)$", value, re.I)
            path = github_match.group(1) if github_match else value

    path = path.split("?", 1)[0].split("#", 1)[0].strip("/")
    parts = path.split("/")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        return ""
    owner = parts[0]
    repo = parts[1].split("@", 1)[0]
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo:
        return ""
    return f"{owner}/{repo}".lower()


def _extract_repository(
    build_definition: Mapping[str, Any],
) -> str:
    """Extract a repository from SLSA v1 or legacy predicate fields."""
    external = build_definition.get("externalParameters", {})
    if isinstance(external, Mapping):
        source = external.get("source")
        if isinstance(source, Mapping):
            for key in ("repository", "uri", "url"):
                candidate = _string(source.get(key))
                if candidate:
                    return candidate
        elif isinstance(source, str) and source.strip():
            return source.strip()

        workflow = external.get("workflow")
        if isinstance(workflow, Mapping):
            candidate = _string(workflow.get("repository"))
            if candidate:
                return candidate

    dependencies = build_definition.get("resolvedDependencies")
    if _is_sequence(dependencies):
        for dependency in dependencies:
            if isinstance(dependency, Mapping):
                candidate = _string(dependency.get("uri"))
                if candidate:
                    return candidate
    return ""


def _extract_commit(predicate: Mapping[str, Any]) -> str:
    """Extract a Git commit from SLSA v1 dependencies or legacy materials."""
    build_definition = predicate.get("buildDefinition", {})
    if isinstance(build_definition, Mapping):
        dependencies = build_definition.get("resolvedDependencies")
        commit = _commit_from_dependencies(dependencies)
        if commit:
            return commit
    return _commit_from_dependencies(predicate.get("materials"))


def _commit_from_dependencies(dependencies: Any) -> str:
    if not _is_sequence(dependencies):
        return ""
    for dependency in dependencies:
        if not isinstance(dependency, Mapping):
            continue
        digest = dependency.get("digest")
        if not isinstance(digest, Mapping):
            continue
        for key in ("gitCommit", "sha1", "sha256"):
            candidate = _string(digest.get(key))
            if candidate:
                return candidate
    return ""


def _extract_workflow_path(build_definition: Mapping[str, Any]) -> str:
    """Extract a workflow path from SLSA v1 or legacy parameters."""
    for section_name in ("externalParameters", "internalParameters"):
        section = build_definition.get(section_name, {})
        if not isinstance(section, Mapping):
            continue
        workflow = section.get("workflow")
        if isinstance(workflow, Mapping):
            candidate = _string(workflow.get("path"))
            if candidate:
                return candidate
        elif isinstance(workflow, str) and workflow.strip():
            return workflow.strip()
        for key in ("workflowPath", "workflow_path"):
            candidate = _string(section.get(key))
            if candidate:
                return candidate
    return ""


def _extract_tlog_metadata(document: Mapping[str, Any]) -> tuple[int, int]:
    """Return ``(log_index, integrated_time)`` from the first Rekor entry."""
    bundle = _select_bundle(document)
    verification = _as_mapping(
        bundle.get("verificationMaterial"), "verificationMaterial"
    )
    entries = verification.get("tlogEntries")
    if entries is None:
        entries = verification.get("transparencyLogEntries")
    if not _is_sequence(entries) or not entries:
        raise BundleParseError("tlogEntries is missing or empty")

    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        try:
            log_index = int(entry["logIndex"])
            integrated_time = int(entry["integratedTime"])
        except (KeyError, TypeError, ValueError) as exc:
            raise BundleParseError("invalid Rekor log metadata") from exc
        if log_index < 0 or integrated_time < 0:
            raise BundleParseError("Rekor log metadata cannot be negative")
        return log_index, integrated_time
    raise BundleParseError("tlogEntries contains no usable entry")


def parse_sigstore_bundle(bundle_filepath: str) -> dict[str, Any]:
    """Parse an npm Sigstore provenance response into TrustGate's schema.

    Any malformed bundle, missing critical evidence, or contradictory lineage
    data produces an ``UNVERIFIABLE`` result.
    """
    result = _empty_result()

    try:
        with Path(bundle_filepath).open("r", encoding="utf-8") as bundle_file:
            document = _as_mapping(json.load(bundle_file), "bundle document")

        predicate = _decode_payload(document)
        build_definition_value = predicate.get("buildDefinition", {})
        build_definition = _as_mapping(
            build_definition_value, "predicate.buildDefinition"
        )

        run_details = predicate.get("runDetails", {})
        run_details = _as_mapping(run_details, "predicate.runDetails")
        builder_value = run_details.get("builder", predicate.get("builder", {}))
        builder = _as_mapping(builder_value, "predicate builder")

        predicate_repository = _normalize_repository(
            _extract_repository(build_definition)
        )
        predicate_commit = _extract_commit(predicate)

        certificate = _load_certificate(document)
        claims: dict[str, str] = {}
        certificate_subject = ""
        if certificate is not None:
            claims = _certificate_claims(certificate)
            certificate_subject = _certificate_san_uri(certificate)

        certificate_repository = _normalize_repository(
            claims.get(_OID_REPOSITORY, "")
        )
        certificate_commit = claims.get(_OID_WORKFLOW_SHA, "")
        log_index, _integrated_time = _extract_tlog_metadata(document)

        result["oidc"] = {
            "issuer": claims.get(_OID_ISSUER, ""),
            "subject": certificate_subject,
            "repository": certificate_repository,
            "workflow": certificate_commit,
        }
        result["builder"] = {
            "id": _string(builder.get("id")),
            "workflow_path": _extract_workflow_path(build_definition),
        }
        result["verified_commit"] = certificate_commit or predicate_commit
        result["rekor_log_index"] = log_index

        required_output = (
            result["oidc"]["issuer"],
            result["oidc"]["subject"],
            result["oidc"]["repository"],
            result["oidc"]["workflow"],
            result["builder"]["id"],
            result["verified_commit"],
        )
        repositories_match = (
            bool(predicate_repository)
            and predicate_repository == certificate_repository
        )
        commits_match = (
            bool(predicate_commit)
            and predicate_commit.lower() == certificate_commit.lower()
        )
        if all(required_output) and repositories_match and commits_match:
            result["status"] = "PASS"
    except (OSError, TypeError, ValueError, json.JSONDecodeError):
        result["status"] = "UNVERIFIABLE"

    return result


__all__ = ["parse_sigstore_bundle"]
