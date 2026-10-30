"""Versioned on-disk record envelope (JSON, no plaintext)."""

from __future__ import annotations

import base64
import json
from typing import Any

from genesis_plugin.crypto_vault.canonical import (
    AAD_SCHEMA,
    CANONICAL_JSON_VERSION,
    CANONICAL_PLAINTEXT_VERSION,
    ENVELOPE_SCHEMA,
    ENVELOPE_VERSION,
    canonical_json_bytes,
)
from genesis_plugin.crypto_vault.exceptions import EnvelopeError
from genesis_plugin.crypto_vault.integrity import sha256_hex

REQUIRED_FIELDS = (
    "schema",
    "version",
    "record_id",
    "canonical_plaintext_version",
    "canonical_json_version",
    "caller_aad_b64",
    "nonce_b64",
    "ciphertext_b64",
    "content_sha256",
    "signer_key_id",
    "signature_b64",
)


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(value: str, *, what: str) -> bytes:
    if not isinstance(value, str):
        raise EnvelopeError(f"Envelope field {what} is invalid.")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise EnvelopeError(f"Envelope field {what} is invalid.") from exc


def build_aad(record_id: str, caller_aad: bytes | None) -> bytes:
    """AAD binds record ID and optional caller-supplied associated data."""
    return canonical_json_bytes(
        {
            "caller_aad_b64": b64encode(caller_aad) if caller_aad else None,
            "record_id": record_id,
            "schema": AAD_SCHEMA,
            "version": 1,
        }
    )


def build_envelope(
    *,
    record_id: str,
    canonical_plaintext_version: int,
    caller_aad: bytes | None,
    nonce: bytes,
    ciphertext: bytes,
    content_sha256: str,
    signer_key_id: str,
    signature: bytes,
) -> dict[str, Any]:
    return {
        "schema": ENVELOPE_SCHEMA,
        "version": ENVELOPE_VERSION,
        "record_id": record_id,
        "canonical_plaintext_version": canonical_plaintext_version,
        "canonical_json_version": CANONICAL_JSON_VERSION,
        "caller_aad_b64": b64encode(caller_aad) if caller_aad else None,
        "nonce_b64": b64encode(nonce),
        "ciphertext_b64": b64encode(ciphertext),
        "content_sha256": content_sha256,
        "signer_key_id": signer_key_id,
        "signature_b64": b64encode(signature),
    }


def parse_envelope(raw: bytes) -> dict[str, Any]:
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EnvelopeError("Envelope is not valid JSON.") from exc
    if not isinstance(obj, dict):
        raise EnvelopeError("Envelope is not a JSON object.")
    for field in REQUIRED_FIELDS:
        if field not in obj:
            raise EnvelopeError("Envelope is missing required fields.")
    if obj["schema"] != ENVELOPE_SCHEMA:
        raise EnvelopeError("Envelope schema is unsupported.")
    if obj["version"] != ENVELOPE_VERSION:
        raise EnvelopeError("Envelope version is unsupported.")
    if obj["canonical_plaintext_version"] != CANONICAL_PLAINTEXT_VERSION:
        raise EnvelopeError("Canonical plaintext version is unsupported.")
    if obj["canonical_json_version"] != CANONICAL_JSON_VERSION:
        raise EnvelopeError("Canonical JSON version is unsupported.")
    if not isinstance(obj["record_id"], str) or not obj["record_id"]:
        raise EnvelopeError("Envelope record_id is invalid.")
    if not isinstance(obj["content_sha256"], str) or len(obj["content_sha256"]) != 64:
        raise EnvelopeError("Envelope content digest is invalid.")
    if not isinstance(obj["signer_key_id"], str) or len(obj["signer_key_id"]) != 64:
        raise EnvelopeError("Envelope signer_key_id is invalid.")
    if obj["caller_aad_b64"] is not None and not isinstance(obj["caller_aad_b64"], str):
        raise EnvelopeError("Envelope caller AAD is invalid.")
    return obj


def envelope_crypto_fields(obj: dict[str, Any]) -> tuple[bytes, bytes, bytes | None, bytes]:
    nonce = b64decode(obj["nonce_b64"], what="nonce")
    ciphertext = b64decode(obj["ciphertext_b64"], what="ciphertext")
    caller_aad = None
    if obj["caller_aad_b64"] is not None:
        caller_aad = b64decode(obj["caller_aad_b64"], what="caller_aad")
    signature = b64decode(obj["signature_b64"], what="signature")
    return nonce, ciphertext, caller_aad, signature


def aad_digest(aad: bytes) -> str:
    return sha256_hex(aad)
