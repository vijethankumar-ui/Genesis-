import gzip

import pytest

from privacy.data_loader import (
    find_variant_records,
    iter_variant_records,
)


def create_test_vcf(path):
    """Create a small compressed VCF for predictable tests."""
    content = (
        "##fileformat=VCFv4.2\n"
        "#CHROM\tPOS\tID\tREF\tALT\tQUAL\tFILTER\tINFO\tFORMAT\tSAMPLE1\n"
        "22\t100\trs-first\tA\tG\t.\tPASS\t.\tGT\t0/1\n"
        "22\t200\trs-second\tC\tT\t.\tPASS\t.\tGT\t1/1\n"
        "22\t300\trs-third\tG\tA\t.\tPASS\t.\tGT\t0/0\n"
        "22\t400\trs-second\tT\tC\t.\tPASS\t.\tGT\t0/1\n"
    )

    with gzip.open(path, "wt") as vcf:
        vcf.write(content)


def test_load_real_vcf_records(tmp_path):
    vcf_path = tmp_path / "test.vcf.gz"
    create_test_vcf(vcf_path)
    records = list(iter_variant_records(vcf_path, limit=3))

    assert len(records) == 3

    for record in records:
        assert record["chromosome"] == "22"
        assert isinstance(record["position"], int)
        assert record["position"] > 0
        assert record["reference"]
        assert record["alternate"]
        assert record["genotypes"]


def test_genotypes_have_valid_vcf_format(tmp_path):
    vcf_path = tmp_path / "test.vcf.gz"
    create_test_vcf(vcf_path)
    records = list(iter_variant_records(vcf_path, limit=3))

    for record in records:
        for genotype in record["genotypes"].values():
            assert genotype in {
                "0|0", "0|1", "1|0", "1|1",
                "0/0", "0/1", "1/0", "1/1",
                "./.", ".|.",
            } or genotype.startswith(".")


def test_limit_must_be_positive():
    with pytest.raises(ValueError):
        list(iter_variant_records(limit=0))


def test_find_variant_records_finds_matching_variant(tmp_path):
    vcf_path = tmp_path / "test.vcf.gz"
    create_test_vcf(vcf_path)

    records = find_variant_records(vcf_path, "rs-third")

    assert len(records) == 1
    assert records[0]["position"] == 300
    assert records[0]["genotypes"]["SAMPLE1"] == "0/0"


def test_find_variant_records_returns_all_duplicate_ids(tmp_path):
    vcf_path = tmp_path / "test.vcf.gz"
    create_test_vcf(vcf_path)

    records = find_variant_records(vcf_path, "rs-second")

    assert len(records) == 2
    assert [record["position"] for record in records] == [200, 400]


def test_find_variant_records_returns_empty_for_missing_id(tmp_path):
    vcf_path = tmp_path / "test.vcf.gz"
    create_test_vcf(vcf_path)

    assert find_variant_records(vcf_path, "rs-absent") == []


@pytest.mark.parametrize("variant_id", ["", "   "])
def test_find_variant_records_rejects_empty_id(tmp_path, variant_id):
    vcf_path = tmp_path / "test.vcf.gz"
    create_test_vcf(vcf_path)

    with pytest.raises(ValueError, match="variant_id must not be empty"):
        find_variant_records(vcf_path, variant_id)
