
import pytest

from privacy.disclosure_budget import DisclosureBudget
from privacy.protected_query import execute_protected_query


@pytest.fixture
def budget(tmp_path):
    return DisclosureBudget(
        db_path=tmp_path / "test_budget.db",
        default_limit=2,
    )


@pytest.fixture
def records():
    return [
        {
            "chromosome": "22",
            "position": 16050213,
            "variant_id": "rs123",
            "reference": "C",
            "alternate": "T",
            "genotypes": {
                "sample-001": "0/1",
                "sample-002": "0/0",
            },
        }
    ]


def run_query(records, budget, **overrides):
    arguments = {
        "records": records,
        "query_type": "variant_presence",
        "variant_id": "rs123",
        "budget": budget,
        "participant_id": "participant-001",
        "requester_id": "researcher-001",
        "project_id": "project-001",
        "purpose": "approved_research",
        "consent_id": "consent-001",
        "sample_id": "sample-001",
    }
    arguments.update(overrides)
    return execute_protected_query(**arguments)


def test_valid_query_returns_minimal_answer(records, budget):
    result = run_query(records, budget)

    assert result is True

    status = budget.get_status(
        "participant-001",
        "researcher-001",
        "project-001",
        "approved_research",
        "consent-001",
    )
    assert status["used"] == 1
    assert status["remaining"] == 1


def test_exhausted_budget_blocks_answer(records, budget):
    run_query(records, budget)
    run_query(records, budget)

    with pytest.raises(PermissionError, match="budget exhausted"):
        run_query(records, budget)

    status = budget.get_status(
        "participant-001",
        "researcher-001",
        "project-001",
        "approved_research",
        "consent-001",
    )
    assert status["used"] == 2
    assert status["remaining"] == 0


def test_invalid_query_does_not_consume_budget(records, budget):
    with pytest.raises(ValueError, match="Unsupported query type"):
        run_query(
            records,
            budget,
            query_type="raw_records",
        )

    status = budget.get_status(
        "participant-001",
        "researcher-001",
        "project-001",
        "approved_research",
        "consent-001",
    )
    assert status["used"] == 0
