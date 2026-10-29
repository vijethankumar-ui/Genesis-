"""SHA-256 content digest over canonical plaintext bytes.

An unkeyed hash is not an authenticity proof. Authenticity comes from Ed25519
over the signed payload, plus AES-GCM authentication of the ciphertext.
"""

from __future__ import annotations

import hashlib


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def content_digest(plaintext: bytes) -> str:
    """SHA-256 of the exact caller-supplied plaintext bytes (canonical v1)."""
    return sha256_hex(plaintext)
