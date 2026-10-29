
import pytest

from privacy.query_engine import execute_query


RECORDS = [
    {
        "variant_id": "rs123",
        "genotypes": {
            "HG00096": "0|1",
            "HG00097": "0|0",
            "HG00098": "1|1",
            "HG00099": "./.",
        },
    }
]


def test_sample_carries_variant():
    assert execute_query(
        RECORDS, "variant_presence", "rs123", "HG00096"
    ) is True


def test_sample_does_not_carry_variant():
    assert execute_query(
        RECORDS, "variant_presence", "rs123", "HG00097"
    ) is False


def test_variant_count_counts_carriers():
    assert execute_query(
        RECORDS, "variant_count", "rs123"
    ) == 2


def test_unknown_sample_is_rejected():
    with pytest.raises(ValueError, match="Unknown sample ID"):
        execute_query(
            RECORDS, "variant_presence", "rs123", "UNKNOWN"
        )


def test_presence_requires_sample_id():
    with pytest.raises(ValueError, match="sample_id is required"):
        execute_query(RECORDS, "variant_presence", "rs123")


def test_unsupported_query_type():
    with pytest.raises(ValueError, match="Unsupported query type"):
        execute_query(RECORDS, "raw_records", "rs123")


def test_empty_variant_id():
    with pytest.raises(ValueError, match="variant_id must not be empty"):
        execute_query(RECORDS, "variant_presence", " ", "HG00096")


def test_missing_genotype_is_not_counted_as_carrier():
    records = [
        {
            "variant_id": "rs-missing",
            "genotypes": {
                "sample-001": "./.",
                "sample-002": ".|.",
            },
        }
    ]

    assert execute_query(
        records, "variant_count", "rs-missing"
    ) == 0


def test_homozygous_alternate_genotype_counts_as_one_carrier():
    records = [
        {
            "variant_id": "rs-hom",
            "genotypes": {
                "sample-001": "1/1",
                "sample-002": "0/1",
                "sample-003": "0/0",
            },
        }
    ]

    assert execute_query(
        records, "variant_count", "rs-hom"
    ) == 2


def test_variant_not_found_returns_zero_count():
    assert execute_query(
        RECORDS, "variant_count", "rs-not-present"
    ) == 0


def test_missing_variant_presence_returns_false_for_known_sample():
    assert execute_query(
        RECORDS,
        "variant_presence",
        "rs-not-present",
        "HG00096",
    ) is False
