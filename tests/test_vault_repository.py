
import json

import pytest

from privacy.vault_repository import VaultRepository


class FakeReleasedRecord:
    def __init__(self, plaintext: bytes):
        self.plaintext = plaintext


class FakeVault:
    """Test double that simulates vault storage and verified release."""

    def __init__(self):
        self.records = {}
        self.release_calls = []

    def store(self, record_id, plaintext):
        self.records[record_id] = plaintext

    def release(self, record_id):
        self.release_calls.append(record_id)
        if record_id not in self.records:
            raise KeyError(record_id)
        return FakeReleasedRecord(self.records[record_id])


def sample_record():
    return {
        "variant_id": "rs-test-123",
        "chromosome": "22",
        "position": 12345,
        "reference": "A",
        "alternate": "G",
        "genotypes": {"sample-1": "0/1"},
    }


def test_store_and_retrieve_record():
    vault = FakeVault()
    repository = VaultRepository(vault)
    record = sample_record()

    repository.store_record(record)
    retrieved = repository.get_variant_records("rs-test-123")

    assert retrieved == [record]
    assert len(vault.release_calls) == 1


def test_unknown_variant_returns_empty_list():
    repository = VaultRepository(FakeVault())

    assert repository.get_variant_records("rs-missing") == []


def test_invalid_variant_id_is_rejected():
    repository = VaultRepository(FakeVault())

    with pytest.raises(ValueError, match="variant_id"):
        repository.get_variant_records(" ")


def test_record_with_missing_variant_id_is_rejected():
    repository = VaultRepository(FakeVault())

    with pytest.raises(ValueError, match="variant_id"):
        repository.store_record({"genotypes": {}})


def test_mismatched_variant_record_is_rejected():
    vault = FakeVault()
    repository = VaultRepository(vault)
    record_id = repository.store_record(sample_record())

    # Simulate a released payload that doesn't match the requested variant.
    vault.records[record_id] = json.dumps({
        **sample_record(),
        "variant_id": "rs-other",
    }).encode("utf-8")

    with pytest.raises(ValueError, match="mismatch"):
        repository.get_variant_records("rs-test-123")

def test_index_survives_repository_reinitialization(tmp_path):
    vault = FakeVault()
    index_path = tmp_path / "variant_index.db"
    record = sample_record()

    first_repository = VaultRepository(vault, index_path=index_path)
    first_repository.store_record(record)

    second_repository = VaultRepository(vault, index_path=index_path)

    assert second_repository.get_variant_records("rs-test-123") == [record]


def test_vault_release_failure_propagates(tmp_path):
    vault = FakeVault()
    repository = VaultRepository(
        vault,
        index_path=tmp_path / "variant_index.db",
    )
    repository.store_record(sample_record())

    def fail_release(record_id):
        raise RuntimeError("Simulated vault release failure")

    vault.release = fail_release

    with pytest.raises(RuntimeError, match="release failure"):
        repository.get_variant_records("rs-test-123")
