from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from genesis_plugin.crypto_vault.keys import VaultKeys, public_key_id
from genesis_plugin.crypto_vault.vault import StorageVault

FIXTURES = Path(__file__).parent / "fixtures"
SYNTHETIC_PATH = FIXTURES / "synthetic_records.json"


@pytest.fixture
def synthetic_plaintext() -> bytes:
    return SYNTHETIC_PATH.read_bytes()


@pytest.fixture
def vault_keys() -> VaultKeys:
    encryption_key = os.urandom(32)
    signing_key = Ed25519PrivateKey.generate()
    public = signing_key.public_key()
    return VaultKeys(
        encryption_key=encryption_key,
        signing_key=signing_key,
        trusted_public_keys={public_key_id(public): public},
    )


@pytest.fixture
def vault(tmp_path: Path, vault_keys: VaultKeys) -> StorageVault:
    return StorageVault(tmp_path / "vault", vault_keys)
