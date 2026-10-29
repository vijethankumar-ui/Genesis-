from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from genesis_plugin.crypto_vault.exceptions import SignatureError
from genesis_plugin.crypto_vault.signatures import sign, signed_payload, verify_signature


def _payload() -> bytes:
    return signed_payload(
        record_id="syn-1",
        content_sha256="a" * 64,
        canonical_plaintext_version=1,
        aad_sha256="b" * 64,
        nonce_b64="AAAAAAAAAAAA",
        ciphertext_sha256="c" * 64,
        envelope_version=1,
        signer_key_id="d" * 64,
    )


def test_sign_and_verify() -> None:
    key = Ed25519PrivateKey.generate()
    payload = _payload()
    signature = sign(key, payload)
    verify_signature(key.public_key(), payload, signature)


def test_invalid_signature_rejected() -> None:
    key = Ed25519PrivateKey.generate()
    payload = _payload()
    signature = bytearray(sign(key, payload))
    signature[0] ^= 0x01
    with pytest.raises(SignatureError):
        verify_signature(key.public_key(), payload, bytes(signature))


def test_wrong_public_key_rejected() -> None:
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate()
    payload = _payload()
    signature = sign(key, payload)
    with pytest.raises(SignatureError):
        verify_signature(other.public_key(), payload, signature)


def test_metadata_change_breaks_signature() -> None:
    key = Ed25519PrivateKey.generate()
    payload = _payload()
    signature = sign(key, payload)
    altered = signed_payload(
        record_id="syn-2",
        content_sha256="a" * 64,
        canonical_plaintext_version=1,
        aad_sha256="b" * 64,
        nonce_b64="AAAAAAAAAAAA",
        ciphertext_sha256="c" * 64,
        envelope_version=1,
        signer_key_id="d" * 64,
    )
    with pytest.raises(SignatureError):
        verify_signature(key.public_key(), altered, signature)
