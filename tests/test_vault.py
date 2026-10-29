from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from genesis_plugin.crypto_vault.envelope import (
    aad_digest,
    b64decode,
    b64encode,
    build_aad,
    envelope_crypto_fields,
    parse_envelope,
)
from genesis_plugin.crypto_vault.exceptions import (
    DecryptionError,
    EnvelopeError,
    IntegrityError,
    InvalidRecordId,
    KeyConfigError,
    RecordNotFound,
    SignatureError,
)
from genesis_plugin.crypto_vault.integrity import content_digest, sha256_hex
from genesis_plugin.crypto_vault.keys import VaultKeys, public_key_id
from genesis_plugin.crypto_vault.signatures import sign, signed_payload
from genesis_plugin.crypto_vault.types import VerifyResult
from genesis_plugin.crypto_vault.vault import StorageVault


def _envelope_path(vault: StorageVault, record_id: str) -> Path:
    return vault._record_path(record_id)


def _read_envelope(vault: StorageVault, record_id: str) -> dict:
    return json.loads(_envelope_path(vault, record_id).read_text(encoding="utf-8"))


def _write_envelope(vault: StorageVault, record_id: str, obj: dict) -> None:
    _envelope_path(vault, record_id).write_text(json.dumps(obj), encoding="utf-8")


def test_store_release_round_trip(vault: StorageVault, synthetic_plaintext: bytes) -> None:
    receipt = vault.store("syn-0001", synthetic_plaintext, aad=b"research")
    assert receipt.record_id == "syn-0001"
    assert receipt.content_sha256 == content_digest(synthetic_plaintext)
    result = vault.verify("syn-0001")
    assert result.ok is True
    released = vault.release("syn-0001")
    assert released.plaintext == synthetic_plaintext


def test_stored_file_does_not_contain_plaintext(
    vault: StorageVault, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    stored = _envelope_path(vault, "syn-0001").read_bytes()
    assert synthetic_plaintext not in stored
    assert b"SYNTH-0001" not in stored
    assert b"55249071" not in stored


def test_missing_record(vault: StorageVault) -> None:
    with pytest.raises(RecordNotFound):
        vault.verify("missing-record")
    with pytest.raises(RecordNotFound):
        vault.release("missing-record")


def test_malformed_envelope(vault: StorageVault, synthetic_plaintext: bytes) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    _envelope_path(vault, "syn-0001").write_text("{not-json", encoding="utf-8")
    with pytest.raises(EnvelopeError):
        vault.verify("syn-0001")


def test_malformed_envelope_missing_fields(vault: StorageVault, synthetic_plaintext: bytes) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    _write_envelope(vault, "syn-0001", {"schema": "genesis.vault.envelope", "version": 1})
    with pytest.raises(EnvelopeError):
        vault.release("syn-0001")


def test_modified_ciphertext_prevents_release(
    vault: StorageVault, vault_keys: VaultKeys, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    obj = _read_envelope(vault, "syn-0001")
    raw = bytearray(b64decode(obj["ciphertext_b64"], what="ciphertext"))
    raw[0] ^= 0x01
    obj["ciphertext_b64"] = b64encode(bytes(raw))
    _write_envelope(vault, "syn-0001", obj)
    with pytest.raises(SignatureError):
        vault.release("syn-0001")


def test_modified_ciphertext_with_resign_fails_decrypt(
    vault: StorageVault, vault_keys: VaultKeys, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext, aad=b"purpose")
    obj = _read_envelope(vault, "syn-0001")
    nonce, ciphertext, caller_aad, _sig = envelope_crypto_fields(obj)
    tampered = bytes([ciphertext[0] ^ 0x01]) + ciphertext[1:]
    obj["ciphertext_b64"] = b64encode(tampered)
    aad = build_aad("syn-0001", caller_aad)
    payload = signed_payload(
        record_id="syn-0001",
        content_sha256=obj["content_sha256"],
        canonical_plaintext_version=obj["canonical_plaintext_version"],
        aad_sha256=aad_digest(aad),
        nonce_b64=obj["nonce_b64"],
        ciphertext_sha256=sha256_hex(tampered),
        envelope_version=obj["version"],
        signer_key_id=obj["signer_key_id"],
    )
    obj["signature_b64"] = b64encode(sign(vault_keys.signing_key, payload))
    _write_envelope(vault, "syn-0001", obj)
    with pytest.raises(DecryptionError):
        vault.release("syn-0001")


def test_incorrect_aad_fails(
    vault: StorageVault, vault_keys: VaultKeys, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext, aad=b"purpose-a")
    obj = _read_envelope(vault, "syn-0001")
    obj["caller_aad_b64"] = b64encode(b"purpose-b")
    aad = build_aad("syn-0001", b"purpose-b")
    nonce, ciphertext, _old, _sig = envelope_crypto_fields(parse_envelope(json.dumps(obj).encode()))
    payload = signed_payload(
        record_id="syn-0001",
        content_sha256=obj["content_sha256"],
        canonical_plaintext_version=obj["canonical_plaintext_version"],
        aad_sha256=aad_digest(aad),
        nonce_b64=obj["nonce_b64"],
        ciphertext_sha256=sha256_hex(ciphertext),
        envelope_version=obj["version"],
        signer_key_id=obj["signer_key_id"],
    )
    obj["signature_b64"] = b64encode(sign(vault_keys.signing_key, payload))
    _write_envelope(vault, "syn-0001", obj)
    with pytest.raises(DecryptionError):
        vault.release("syn-0001")


def test_incorrect_content_digest(
    vault: StorageVault, vault_keys: VaultKeys, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    obj = _read_envelope(vault, "syn-0001")
    obj["content_sha256"] = "ab" * 32
    nonce, ciphertext, caller_aad, _sig = envelope_crypto_fields(obj)
    aad = build_aad("syn-0001", caller_aad)
    payload = signed_payload(
        record_id="syn-0001",
        content_sha256=obj["content_sha256"],
        canonical_plaintext_version=obj["canonical_plaintext_version"],
        aad_sha256=aad_digest(aad),
        nonce_b64=obj["nonce_b64"],
        ciphertext_sha256=sha256_hex(ciphertext),
        envelope_version=obj["version"],
        signer_key_id=obj["signer_key_id"],
    )
    obj["signature_b64"] = b64encode(sign(vault_keys.signing_key, payload))
    _write_envelope(vault, "syn-0001", obj)
    with pytest.raises(IntegrityError):
        vault.release("syn-0001")


def test_invalid_signature(vault: StorageVault, synthetic_plaintext: bytes) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    obj = _read_envelope(vault, "syn-0001")
    raw = bytearray(b64decode(obj["signature_b64"], what="signature"))
    raw[0] ^= 0x01
    obj["signature_b64"] = b64encode(bytes(raw))
    _write_envelope(vault, "syn-0001", obj)
    with pytest.raises(SignatureError):
        vault.verify("syn-0001")


def test_untrusted_signer_rejected(
    vault: StorageVault, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    obj = _read_envelope(vault, "syn-0001")
    attacker = Ed25519PrivateKey.generate()
    nonce, ciphertext, caller_aad, _sig = envelope_crypto_fields(obj)
    aad = build_aad("syn-0001", caller_aad)
    payload = signed_payload(
        record_id="syn-0001",
        content_sha256=obj["content_sha256"],
        canonical_plaintext_version=obj["canonical_plaintext_version"],
        aad_sha256=aad_digest(aad),
        nonce_b64=obj["nonce_b64"],
        ciphertext_sha256=sha256_hex(ciphertext),
        envelope_version=obj["version"],
        signer_key_id=public_key_id(attacker.public_key()),
    )
    obj["signer_key_id"] = public_key_id(attacker.public_key())
    obj["signature_b64"] = b64encode(sign(attacker, payload))
    _write_envelope(vault, "syn-0001", obj)
    with pytest.raises(SignatureError):
        vault.release("syn-0001")


def test_record_id_substitution(vault: StorageVault, synthetic_plaintext: bytes) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    original = _read_envelope(vault, "syn-0001")
    vault.store("syn-0002", b"other-synthetic")
    _write_envelope(vault, "syn-0002", original)
    with pytest.raises(EnvelopeError):
        vault.release("syn-0002")


def test_signed_metadata_substitution(
    vault: StorageVault, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    obj = _read_envelope(vault, "syn-0001")
    obj["record_id"] = "syn-0001"
    obj["canonical_plaintext_version"] = 1
    # Change a signed field (nonce) without updating the signature.
    nonce = bytearray(b64decode(obj["nonce_b64"], what="nonce"))
    nonce[0] ^= 0x01
    obj["nonce_b64"] = b64encode(bytes(nonce))
    _write_envelope(vault, "syn-0001", obj)
    with pytest.raises(SignatureError):
        vault.release("syn-0001")


def test_path_traversal_rejected(vault: StorageVault, synthetic_plaintext: bytes) -> None:
    for bad in ("../secret", "..\\secret", "foo/bar", "..", "", "a" * 129, "id with space"):
        with pytest.raises(InvalidRecordId):
            vault.store(bad, synthetic_plaintext)
        with pytest.raises(InvalidRecordId):
            vault.verify(bad)


def test_from_env_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, synthetic_plaintext: bytes
) -> None:
    from genesis_plugin.crypto_vault.keys import generate_dev_keys

    key_dir = tmp_path / "keys"
    paths = generate_dev_keys(key_dir)
    vault_dir = tmp_path / "vault-data"
    monkeypatch.setenv("GENESIS_VAULT_DIR", str(vault_dir))
    monkeypatch.setenv("GENESIS_MASTER_KEY_FILE", str(paths["master"]))
    monkeypatch.setenv("GENESIS_SIGNING_KEY_FILE", str(paths["signing"]))
    monkeypatch.setenv("GENESIS_TRUSTED_PUBLIC_KEY_FILE", str(paths["public"]))
    vault = StorageVault.from_env()
    vault.store("syn-env", synthetic_plaintext)
    assert vault.release("syn-env").plaintext == synthetic_plaintext


def test_from_env_missing_vault_dir(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("GENESIS_VAULT_DIR", raising=False)
    with pytest.raises(KeyConfigError):
        StorageVault.from_env()


def test_verify_does_not_return_plaintext(vault: StorageVault, synthetic_plaintext: bytes) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    result = vault.verify("syn-0001")
    assert isinstance(result, VerifyResult)
    assert not hasattr(result, "plaintext")
    assert result.ok is True
