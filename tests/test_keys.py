from __future__ import annotations

import os
from pathlib import Path

import pytest

from genesis_plugin.crypto_vault.exceptions import KeyConfigError
from genesis_plugin.crypto_vault.keys import (
    generate_dev_keys,
    load_encryption_key,
    load_signing_key,
    load_vault_keys_from_env,
)


def test_invalid_encryption_key_length() -> None:
    with pytest.raises(KeyConfigError):
        load_encryption_key(value=os.urandom(16).hex())


def test_invalid_signing_key() -> None:
    with pytest.raises(KeyConfigError):
        load_signing_key(value="00" * 16)


def test_generate_dev_keys_and_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    paths = generate_dev_keys(tmp_path / "keys")
    monkeypatch.setenv("GENESIS_MASTER_KEY_FILE", str(paths["master"]))
    monkeypatch.setenv("GENESIS_SIGNING_KEY_FILE", str(paths["signing"]))
    monkeypatch.setenv("GENESIS_TRUSTED_PUBLIC_KEY_FILE", str(paths["public"]))
    loaded = load_vault_keys_from_env()
    assert len(loaded.encryption_key) == 32
    assert loaded.signing_key is not None
    assert loaded.trusted_public_keys


def test_refuse_overwrite_keys(tmp_path: Path) -> None:
    generate_dev_keys(tmp_path / "keys")
    with pytest.raises(KeyConfigError):
        generate_dev_keys(tmp_path / "keys")


def test_from_env_does_not_invent_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GENESIS_MASTER_KEY", raising=False)
    monkeypatch.delenv("GENESIS_MASTER_KEY_FILE", raising=False)
    monkeypatch.delenv("GENESIS_SIGNING_KEY", raising=False)
    monkeypatch.delenv("GENESIS_SIGNING_KEY_FILE", raising=False)
    with pytest.raises(KeyConfigError):
        load_vault_keys_from_env()
