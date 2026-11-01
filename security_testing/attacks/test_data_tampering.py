"""Attack 6 - Genomic data tampering.

An attacker alters a stored genomic record (e.g. flips BRCA1 Present -> Absent).
Integrity verification must detect the modification, refuse to release the
record, and record the failure.

SAFETY: tampering is performed only against a DISPOSABLE vault built in a pytest
tmp directory with its own fresh keys. The primary vault is never touched.
"""

import json

import pytest

from genesis_plugin.crypto_vault import StorageVault, VaultError
from genesis_plugin.crypto_vault.keys import (
    VaultKeys,
    generate_dev_keys,
    load_encryption_key,
    load_public_key,
    load_signing_key,
    public_key_id,
)


def _disposable_vault(tmp_path):
    key_paths = generate_dev_keys(tmp_path / "keys")
    enc = load_encryption_key(path=str(key_paths["master"]))
    signing = load_signing_key(path=str(key_paths["signing"]))
    pub = load_public_key(path=str(key_paths["public"]))
    keys = VaultKeys(
        encryption_key=enc,
        signing_key=signing,
        trusted_public_keys={public_key_id(pub): pub},
    )
    return StorageVault(tmp_path / "vault", keys)


def test_tampered_record_is_rejected(tmp_path):
    vault = _disposable_vault(tmp_path)

    record_id = "variant-brca1-test"
    plaintext = json.dumps(
        {"variant_id": "BRCA1", "genotypes": {"HG-T": "1|0"}},  # Present
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")
    vault.store(record_id, plaintext)

    # Baseline: an untampered record releases correctly.
    assert vault.release(record_id).plaintext == plaintext

    # Tamper: rewrite the on-disk envelope (flip the signed content digest).
    record_path = vault._record_path(record_id)
    envelope = json.loads(record_path.read_bytes())
    envelope["content_sha256"] = "0" * 64
    record_path.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n")

    # Integrity verification must fail-closed; no plaintext is returned.
    with pytest.raises(VaultError):
        vault.verify(record_id)
    with pytest.raises(VaultError):
        vault.release(record_id)


def test_tampered_ciphertext_is_rejected(tmp_path):
    vault = _disposable_vault(tmp_path)
    record_id = "variant-ct-test"
    plaintext = b'{"variant_id":"rsCT","genotypes":{"S":"1|1"}}'
    vault.store(record_id, plaintext)

    record_path = vault._record_path(record_id)
    envelope = json.loads(record_path.read_bytes())
    # Corrupt the ciphertext payload (any field name holding the b64 ciphertext).
    ct_field = next(k for k in envelope if "cipher" in k.lower())
    envelope[ct_field] = envelope[ct_field][:-4] + "AAAA"
    record_path.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n")

    with pytest.raises(VaultError):
        vault.release(record_id)
