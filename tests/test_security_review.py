"""Focused security checks for Member 1. Uses synthetic data and tmp dirs only."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from genesis_plugin.crypto_vault.envelope import b64decode, b64encode
from genesis_plugin.crypto_vault.exceptions import (
    DecryptionError,
    EnvelopeError,
    InvalidRecordId,
    KeyConfigError,
    ProvenanceError,
    SignatureError,
    VaultError,
)
from genesis_plugin.crypto_vault.keys import (
    generate_dev_keys,
    load_encryption_key,
    load_signing_key,
    load_vault_keys_from_env,
    public_key_id,
)
from genesis_plugin.crypto_vault.provenance import ProvenanceLog
from genesis_plugin.crypto_vault.types import ReleasedRecord
from genesis_plugin.crypto_vault.vault import StorageVault


def _path(vault: StorageVault, record_id: str) -> Path:
    return vault._record_path(record_id)


def _read(vault: StorageVault, record_id: str) -> dict:
    return json.loads(_path(vault, record_id).read_text(encoding="utf-8"))


def _write(vault: StorageVault, record_id: str, obj: dict) -> None:
    _path(vault, record_id).write_text(json.dumps(obj), encoding="utf-8")


def _assert_no_plaintext_in_exception(exc: BaseException, plaintext: bytes) -> None:
    current: BaseException | None = exc
    marker = b"SYNTH-0001"
    while current is not None:
        text = str(current).encode("utf-8", errors="ignore")
        assert plaintext not in text
        assert marker not in text
        current = current.__cause__ or current.__context__


def _must_not_release(vault: StorageVault, record_id: str, exc_type: type[VaultError], plaintext: bytes) -> None:
    with pytest.raises(exc_type) as caught:
        vault.release(record_id)
    assert not isinstance(caught.value, ReleasedRecord)
    _assert_no_plaintext_in_exception(caught.value, plaintext)
    with pytest.raises(exc_type):
        vault.verify(record_id)


@pytest.mark.parametrize(
    "field",
    [
        "caller_aad_b64",
        "nonce_b64",
        "ciphertext_b64",
        "content_sha256",
        "signer_key_id",
        "signature_b64",
        "record_id",
    ],
)
def test_tamper_each_signed_field_without_resign(
    vault: StorageVault, synthetic_plaintext: bytes, field: str
) -> None:
    vault.store("syn-0001", synthetic_plaintext, aad=b"purpose")
    obj = _read(vault, "syn-0001")
    if field == "record_id":
        obj["record_id"] = "syn-0001"
        # Keep the requested lookup id matching the file, but change a signed
        # copy of the id by using an extra-character still-valid id... the
        # envelope record_id must still match the request or load fails first.
        # Flip signer-bound record_id to another valid id:
        obj["record_id"] = "syn-0009"
        _write(vault, "syn-0001", obj)
        _must_not_release(vault, "syn-0001", EnvelopeError, synthetic_plaintext)
        return
    if field == "caller_aad_b64":
        obj[field] = b64encode(b"other-purpose")
    elif field.endswith("_b64"):
        raw = bytearray(b64decode(obj[field], what=field))
        raw[0] ^= 0x01
        obj[field] = b64encode(bytes(raw))
    else:
        chars = list(obj[field])
        chars[0] = "0" if chars[0] != "0" else "1"
        obj[field] = "".join(chars)
    _write(vault, "syn-0001", obj)
    expected = EnvelopeError if field == "record_id" else SignatureError
    _must_not_release(vault, "syn-0001", expected, synthetic_plaintext)


def test_copy_envelope_and_rewrite_record_id(
    vault: StorageVault, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    stolen = _read(vault, "syn-0001")
    vault.store("syn-0002", b"other-synthetic-record")
    stolen["record_id"] = "syn-0002"
    _write(vault, "syn-0002", stolen)
    _must_not_release(vault, "syn-0002", SignatureError, synthetic_plaintext)


def test_swap_ciphertext_between_valid_records(
    vault: StorageVault, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext, aad=b"a")
    vault.store("syn-0002", b"other-synthetic-record", aad=b"a")
    a = _read(vault, "syn-0001")
    b = _read(vault, "syn-0002")
    b["ciphertext_b64"] = a["ciphertext_b64"]
    b["nonce_b64"] = a["nonce_b64"]
    _write(vault, "syn-0002", b)
    _must_not_release(vault, "syn-0002", SignatureError, synthetic_plaintext)


def test_truncated_and_empty_envelope_fail_closed(
    vault: StorageVault, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    path = _path(vault, "syn-0001")
    original = path.read_bytes()
    path.write_bytes(original[: max(1, len(original) // 3)])
    _must_not_release(vault, "syn-0001", EnvelopeError, synthetic_plaintext)
    path.write_bytes(b"")
    _must_not_release(vault, "syn-0001", EnvelopeError, synthetic_plaintext)
    path.write_bytes(b"\x00\x01\x02not-json")
    _must_not_release(vault, "syn-0001", EnvelopeError, synthetic_plaintext)


def test_schema_and_version_tamper_fail_closed(
    vault: StorageVault, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    obj = _read(vault, "syn-0001")
    obj["schema"] = "genesis.vault.envelope.forged"
    _write(vault, "syn-0001", obj)
    _must_not_release(vault, "syn-0001", EnvelopeError, synthetic_plaintext)
    vault.store("syn-0003", synthetic_plaintext)
    obj = _read(vault, "syn-0003")
    obj["version"] = 99
    _write(vault, "syn-0003", obj)
    _must_not_release(vault, "syn-0003", EnvelopeError, synthetic_plaintext)


def test_wrong_trusted_key_cannot_verify(
    tmp_path: Path, vault_keys, synthetic_plaintext: bytes
) -> None:
    vault = StorageVault(tmp_path / "vault", vault_keys)
    vault.store("syn-0001", synthetic_plaintext)
    other = Ed25519PrivateKey.generate()
    hostile = type(vault_keys)(
        encryption_key=vault_keys.encryption_key,
        signing_key=other,
        trusted_public_keys={public_key_id(other.public_key()): other.public_key()},
    )
    other_vault = StorageVault(tmp_path / "vault", hostile)
    _must_not_release(other_vault, "syn-0001", SignatureError, synthetic_plaintext)


def test_wrong_encryption_key_does_not_release(
    tmp_path: Path, vault_keys, synthetic_plaintext: bytes
) -> None:
    vault = StorageVault(tmp_path / "vault", vault_keys)
    vault.store("syn-0001", synthetic_plaintext)
    wrong = type(vault_keys)(
        encryption_key=os.urandom(32),
        signing_key=vault_keys.signing_key,
        trusted_public_keys=vault_keys.trusted_public_keys,
    )
    other_vault = StorageVault(tmp_path / "vault", wrong)
    _must_not_release(other_vault, "syn-0001", DecryptionError, synthetic_plaintext)


def test_repeated_store_uses_distinct_nonces(
    vault: StorageVault, synthetic_plaintext: bytes
) -> None:
    nonces = []
    for i in range(12):
        rid = f"syn-{i:04d}"
        vault.store(rid, synthetic_plaintext)
        nonces.append(_read(vault, rid)["nonce_b64"])
    assert len(set(nonces)) == 12


def test_invalid_key_files_and_missing_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = tmp_path / "nope.key"
    with pytest.raises(KeyConfigError):
        load_encryption_key(path=str(missing))
    bad = tmp_path / "bad.key"
    bad.write_text("not-a-key\n", encoding="utf-8")
    with pytest.raises(KeyConfigError):
        load_encryption_key(path=str(bad))
    empty = tmp_path / "empty.key"
    empty.write_text("\n", encoding="utf-8")
    with pytest.raises(KeyConfigError):
        load_encryption_key(path=str(empty))
    short = tmp_path / "short.key"
    short.write_text(os.urandom(16).hex(), encoding="utf-8")
    with pytest.raises(KeyConfigError):
        load_encryption_key(path=str(short))
    with pytest.raises(KeyConfigError):
        load_signing_key(path=str(bad))
    monkeypatch.delenv("GENESIS_MASTER_KEY", raising=False)
    monkeypatch.delenv("GENESIS_MASTER_KEY_FILE", raising=False)
    monkeypatch.delenv("GENESIS_SIGNING_KEY", raising=False)
    monkeypatch.delenv("GENESIS_SIGNING_KEY_FILE", raising=False)
    monkeypatch.delenv("GENESIS_TRUSTED_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("GENESIS_TRUSTED_PUBLIC_KEY_FILE", raising=False)
    with pytest.raises(KeyConfigError):
        load_vault_keys_from_env()


def test_explicit_trust_rejects_mismatched_signing_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    a = generate_dev_keys(tmp_path / "keys-a")
    b = generate_dev_keys(tmp_path / "keys-b")
    monkeypatch.setenv("GENESIS_MASTER_KEY_FILE", str(a["master"]))
    monkeypatch.setenv("GENESIS_SIGNING_KEY_FILE", str(a["signing"]))
    monkeypatch.setenv("GENESIS_TRUSTED_PUBLIC_KEY_FILE", str(b["public"]))
    with pytest.raises(KeyConfigError, match="does not match"):
        load_vault_keys_from_env()


def test_gitignore_covers_secrets_and_local_state() -> None:
    text = Path(".gitignore").read_text(encoding="utf-8")
    for pattern in (".venv/", "keys/", "*.key", "*.pem", "vault-data/", ".env"):
        assert pattern in text


def test_provenance_not_mixed_across_records(
    vault: StorageVault, synthetic_plaintext: bytes
) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    vault.store("syn-0002", b"other-synthetic-record")
    events = vault.provenance("syn-0001")
    assert events
    assert all(e.record_id == "syn-0001" for e in events)
    assert all(e.record_id != "syn-0002" for e in events)


def test_provenance_record_id_tamper_detected(tmp_path: Path) -> None:
    log = ProvenanceLog(tmp_path)
    log.append("syn-0001", "store")
    log.append("syn-0002", "store")
    lines = log.path.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[0])
    obj["record_id"] = "syn-9999"
    lines[0] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ProvenanceError):
        log.verify_chain()


def test_provenance_reordered_and_disconnected(tmp_path: Path) -> None:
    log = ProvenanceLog(tmp_path)
    log.append("syn-0001", "store")
    log.append("syn-0001", "verify_ok")
    log.append("syn-0002", "store")
    lines = log.path.read_text(encoding="utf-8").splitlines()
    reordered = [lines[1], lines[0], lines[2]]
    log.path.write_text("\n".join(reordered) + "\n", encoding="utf-8")
    with pytest.raises(ProvenanceError):
        log.verify_chain()
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    obj = json.loads(lines[1])
    obj["prev_hash"] = "0" * 64
    # Keep stored entry_hash so this is a disconnected link, not only a body edit.
    lines[1] = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ProvenanceError):
        log.verify_chain()


def test_invalid_record_ids_do_not_touch_disk(
    vault: StorageVault, synthetic_plaintext: bytes
) -> None:
    records_dir = vault.vault_dir / "records"
    before = set(records_dir.iterdir())
    for bad in ("../secret", "foo/bar", "..", "id with space"):
        with pytest.raises(InvalidRecordId):
            vault.store(bad, synthetic_plaintext)
    after = set(records_dir.iterdir())
    assert before == after
