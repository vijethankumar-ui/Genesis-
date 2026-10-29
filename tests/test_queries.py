
import pytest

from privacy.query_engine import execute_query


RECORDS = [
    {"variant_id": "rs123"},
    {"variant_id": "rs456"},
    {"variant_id": "rs123"},
]


def test_variant_presence_true():
    assert execute_query(
        RECORDS, "variant_presence", "rs123"
    ) is True


def test_variant_presence_false():
    assert execute_query(
        RECORDS, "variant_presence", "rs999"
    ) is False


def test_variant_count():
    assert execute_query(
        RECORDS, "variant_count", "rs123"
    ) == 2


def test_unsupported_query_type():
    with pytest.raises(ValueError):
        execute_query(
            RECORDS, "raw_records", "rs123"
        )


def test_empty_variant_id():
    with pytest.raises(ValueError):
        execute_query(
            RECORDS, "variant_presence", " "
        )
