from __future__ import annotations

from pathlib import Path

import pytest

from genesis_plugin.crypto_vault.exceptions import ProvenanceError
from genesis_plugin.crypto_vault.provenance import ProvenanceLog
from genesis_plugin.crypto_vault.vault import StorageVault


def test_provenance_chain_for_record(vault: StorageVault, synthetic_plaintext: bytes) -> None:
    vault.store("syn-0001", synthetic_plaintext)
    vault.verify("syn-0001")
    vault.release("syn-0001")
    events = vault.provenance("syn-0001")
    assert [e.event_type for e in events] == ["store", "verify_ok", "release_ok"]
    assert events[0].prev_hash == "0" * 64
    assert events[1].prev_hash == events[0].entry_hash
    assert events[2].prev_hash == events[1].entry_hash


def test_broken_provenance_chain_detected(tmp_path: Path) -> None:
    log = ProvenanceLog(tmp_path)
    log.append("syn-0001", "store")
    log.append("syn-0001", "verify_ok")
    text = log.path.read_text(encoding="utf-8")
    lines = text.splitlines()
    lines[0] = lines[0].replace("store", "tampered")
    log.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(ProvenanceError):
        log.verify_chain()


def test_deleted_provenance_entry_detected(tmp_path: Path) -> None:
    log = ProvenanceLog(tmp_path)
    log.append("syn-0001", "store")
    log.append("syn-0001", "verify_ok")
    log.append("syn-0002", "store")
    lines = log.path.read_text(encoding="utf-8").splitlines()
    log.path.write_text(lines[0] + "\n" + lines[2] + "\n", encoding="utf-8")
    with pytest.raises(ProvenanceError):
        log.verify_chain()


def test_malformed_provenance_line(tmp_path: Path) -> None:
    log = ProvenanceLog(tmp_path)
    log.append("syn-0001", "store")
    with log.path.open("a", encoding="utf-8") as handle:
        handle.write("not-json\n")
    with pytest.raises(ProvenanceError):
        log.verify_chain()
