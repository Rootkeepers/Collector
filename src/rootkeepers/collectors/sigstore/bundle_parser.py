"""Utilities for extracting SLSA predicates from Sigstore DSSE bundles."""

import base64
import binascii
import json
from typing import Any


class BundleParseError(Exception):
    """Raised when a Sigstore DSSE bundle cannot be parsed."""


def extract_predicate_from_dsse(document: dict) -> dict:
    """
    Extract the SLSA predicate from a Sigstore DSSE attestation bundle.

    Args:
        document: Parsed JSON dictionary containing either a Sigstore bundle with
            a ``dsseEnvelope`` key or a DSSE envelope directly.

    Returns:
        The decoded statement's ``predicate`` dictionary. If the statement does
        not contain a ``predicate`` key, the entire decoded statement is returned.

    Raises:
        BundleParseError: If the bundle, envelope, payload, or decoded statement
            cannot be parsed safely.
    """
    try:
        if not isinstance(document, dict):
            raise TypeError("document must be a dictionary")

        envelope: dict[str, Any]
        if "dsseEnvelope" in document:
            envelope = document["dsseEnvelope"]
        else:
            envelope = document

        if not isinstance(envelope, dict):
            raise TypeError("dsseEnvelope must be a dictionary")

        payload = envelope["payload"]
        if not isinstance(payload, str):
            raise TypeError("payload must be a Base64-encoded string")

        decoded_payload = base64.b64decode(payload, validate=True).decode("utf-8")
        statement = json.loads(decoded_payload)

        if not isinstance(statement, dict):
            raise TypeError("decoded DSSE payload must be a JSON object")

        predicate = statement.get("predicate")
        if predicate is None:
            return statement

        if not isinstance(predicate, dict):
            raise TypeError("predicate must be a dictionary")

        return predicate

    except BundleParseError:
        raise
    except KeyError as error:
        raise BundleParseError(f"Missing required DSSE field: {error}") from error
    except TypeError as error:
        raise BundleParseError(f"Invalid DSSE bundle structure: {error}") from error
    except binascii.Error as error:
        raise BundleParseError(f"Invalid Base64 DSSE payload: {error}") from error
    except UnicodeDecodeError as error:
        raise BundleParseError(f"DSSE payload is not valid UTF-8: {error}") from error
    except json.JSONDecodeError as error:
        raise BundleParseError(f"Decoded DSSE payload is not valid JSON: {error}") from error
    except Exception as error:
        raise BundleParseError(f"Failed to parse DSSE bundle: {error}") from error
