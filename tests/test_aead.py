from __future__ import annotations

import os

import pytest

from genesis_plugin.crypto_vault import aead
from genesis_plugin.crypto_vault.exceptions import DecryptionError, KeyConfigError


def test_encrypt_decrypt_round_trip() -> None:
    key = os.urandom(32)
    aad = b'{"record_id":"syn-1"}'
    nonce, ciphertext = aead.encrypt(key, b"ACGT", aad)
    assert aead.decrypt(key, nonce, ciphertext, aad) == b"ACGT"


def test_independent_encryptions_use_different_nonces() -> None:
    key = os.urandom(32)
    aad = b"aad"
    nonces = {aead.encrypt(key, b"payload", aad)[0] for _ in range(16)}
    assert len(nonces) == 16
    assert all(len(n) == 12 for n in nonces)


def test_modified_ciphertext_fails() -> None:
    key = os.urandom(32)
    nonce, ciphertext = aead.encrypt(key, b"secret-genome", b"aad")
    tampered = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    with pytest.raises(DecryptionError):
        aead.decrypt(key, nonce, tampered, b"aad")


def test_incorrect_aad_fails() -> None:
    key = os.urandom(32)
    nonce, ciphertext = aead.encrypt(key, b"secret-genome", b"purpose-a")
    with pytest.raises(DecryptionError):
        aead.decrypt(key, nonce, ciphertext, b"purpose-b")


def test_wrong_key_length_rejected() -> None:
    with pytest.raises(KeyConfigError):
        aead.encrypt(os.urandom(16), b"x", b"aad")
