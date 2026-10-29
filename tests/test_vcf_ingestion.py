
from pathlib import Path

from experiments.ingest_vcf_to_vault import ingest_vcf
from privacy.vault_repository import VaultRepository


class FakeVault:
    def __init__(self):
        self.records = {}

    def store(self, record_id, plaintext):
        self.records[record_id] = plaintext

    def release(self, record_id):
        from types import SimpleNamespace

        return SimpleNamespace(plaintext=self.records[record_id])


def test_ingest_vcf_records_into_repository(tmp_path, monkeypatch):
    records = [
        {"variant_id": "rs1", "genotypes": {"sample1": "0/1"}},
        {"variant_id": "rs2", "genotypes": {"sample1": "1/1"}},
    ]

    def fake_iter_variant_records(vcf_path, limit=None):
        yield from records[:limit]

    monkeypatch.setattr(
        "experiments.ingest_vcf_to_vault.iter_variant_records",
        fake_iter_variant_records,
    )

    repository = VaultRepository(
        FakeVault(),
        index_path=tmp_path / "variant_index.db",
    )

    count = ingest_vcf(Path("fake.vcf"), repository, limit=2)

    assert count == 2
    assert repository.get_variant_records("rs1") == [records[0]]
    assert repository.get_variant_records("rs2") == [records[1]]
