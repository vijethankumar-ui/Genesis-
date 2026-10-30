"""Ed25519 signatures over a versioned, deterministic payload."""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from genesis_plugin.crypto_vault.canonical import (
    CANONICAL_JSON_VERSION,
    SIGNED_PAYLOAD_SCHEMA,
    canonical_json_bytes,
)
from genesis_plugin.crypto_vault.exceptions import SignatureError

SIGNED_VERSION = 1


def signed_payload(
    *,
    record_id: str,
    content_sha256: str,
    canonical_plaintext_version: int,
    aad_sha256: str,
    nonce_b64: str,
    ciphertext_sha256: str,
    envelope_version: int,
    signer_key_id: str,
) -> bytes:
    return canonical_json_bytes(
        {
            "aad_sha256": aad_sha256,
            "canonical_json_version": CANONICAL_JSON_VERSION,
            "canonical_plaintext_version": canonical_plaintext_version,
            "ciphertext_sha256": ciphertext_sha256,
            "content_sha256": content_sha256,
            "envelope_version": envelope_version,
            "nonce": nonce_b64,
            "record_id": record_id,
            "schema": SIGNED_PAYLOAD_SCHEMA,
            "signed_version": SIGNED_VERSION,
            "signer_key_id": signer_key_id,
        }
    )


def sign(private_key: Ed25519PrivateKey, payload: bytes) -> bytes:
    return private_key.sign(payload)


def verify_signature(public_key: Ed25519PublicKey, payload: bytes, signature: bytes) -> None:
    try:
        public_key.verify(signature, payload)
    except InvalidSignature as exc:
        raise SignatureError("Signature verification failed.") from exc
    except Exception as exc:
        raise SignatureError("Signature verification failed.") from exc
