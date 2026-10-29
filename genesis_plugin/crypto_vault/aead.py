"""AES-256-GCM with a unique 96-bit nonce per encryption."""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from genesis_plugin.crypto_vault.exceptions import DecryptionError, KeyConfigError

NONCE_LEN = 12
TAG_LEN = 16


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Return ``(nonce, ciphertext_with_tag)``. Nonce is 12 random bytes."""
    if len(key) != 32:
        raise KeyConfigError("Encryption key must be exactly 32 bytes.")
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    if len(key) != 32:
        raise KeyConfigError("Encryption key must be exactly 32 bytes.")
    if len(nonce) != NONCE_LEN:
        raise DecryptionError("Decryption failed.")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise DecryptionError("Decryption failed.") from exc
    except Exception as exc:
        raise DecryptionError("Decryption failed.") from exc
