
from privacy.data_loader import iter_variant_records


def test_load_real_vcf_records():
    records = list(iter_variant_records(limit=3))

    assert len(records) == 3

    for record in records:
        assert record["chromosome"] == "22"
        assert isinstance(record["position"], int)
        assert record["position"] > 0
        assert record["reference"]
        assert record["alternate"]
        assert record["genotypes"]


def test_genotypes_have_valid_vcf_format():
    records = list(iter_variant_records(limit=3))

    for record in records:
        for genotype in record["genotypes"].values():
            assert genotype in {
                "0|0", "0|1", "1|0", "1|1",
                "0/0", "0/1", "1/0", "1/1",
                "./.", ".|.",
            } or genotype.startswith(".")

def test_limit_must_be_positive():
    import pytest

    with pytest.raises(ValueError):
        list(iter_variant_records(limit=0))
