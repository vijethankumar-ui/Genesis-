
from pathlib import Path

import pytest

from privacy.data_loader import iter_variant_records
from privacy.query_engine import execute_query


VCF_PATH = Path(
    "data/raw/ALL.chr22.phase3_shapeit2_mvncall_integrated_v5a.20130502.genotypes.vcf.gz"
)


@pytest.mark.skipif(not VCF_PATH.exists(), reason="Real VCF not downloaded")
def test_real_dataset_query_returns_minimal_answer():
    records = list(iter_variant_records(limit=3))

    assert len(records) == 3

    record = records[0]
    sample_id = next(iter(record["genotypes"]))

    result = execute_query(
        records=records,
        query_type="variant_presence",
        variant_id=record["variant_id"],
        sample_id=sample_id,
    )

    assert isinstance(result, bool)


@pytest.mark.skipif(not VCF_PATH.exists(), reason="Real VCF not downloaded")
def test_real_dataset_variant_count():
    records = list(iter_variant_records(limit=3))
    record = records[0]

    result = execute_query(
        records=records,
        query_type="variant_count",
        variant_id=record["variant_id"],
    )

    assert isinstance(result, int)
    assert 0 <= result <= len(record["genotypes"])
