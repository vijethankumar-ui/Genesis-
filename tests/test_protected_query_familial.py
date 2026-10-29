
import pytest

from privacy.disclosure_budget import DisclosureBudget
from privacy.familial_exposure import FamilialExposure
from privacy.protected_query import execute_protected_query


@pytest.fixture
def setup_engines(tmp_path):
    # Configure a budget that allows exactly one unit of disclosure.
    budget = DisclosureBudget(
        db_path=tmp_path / "disclosure_budget.db",
        default_limit=1,
    )

    exposure = FamilialExposure(
        db_path=tmp_path / "familial_exposure.db"
    )

    exposure.register_relationship(
        "participant-001",
        "participant-002",
        "sibling",
    )

    records = [
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

    return budget, exposure, records


def make_query(budget, exposure, records):
    return execute_protected_query(
        records=records,
        query_type="variant_presence",
        variant_id="rs123",
        budget=budget,
        participant_id="participant-001",
        requester_id="researcher-001",
        project_id="project-001",
        purpose="research",
        consent_id="consent-001",
        sample_id="sample-001",
        cost=1,
        familial_exposure=exposure,
    )


def test_successful_query_records_familial_exposure(setup_engines):
    budget, exposure, records = setup_engines

    result = make_query(budget, exposure, records)

    assert result is True
    assert exposure.get_exposure("participant-001") == 1
    assert exposure.get_exposure("participant-002") == 0


def test_exhausted_budget_does_not_add_exposure(setup_engines):
    budget, exposure, records = setup_engines

    make_query(budget, exposure, records)

    with pytest.raises(PermissionError, match="exhausted"):
        make_query(budget, exposure, records)

    # The rejected query must not add further exposure.
    assert exposure.get_exposure("participant-001") == 1
    assert exposure.get_exposure("participant-002") == 0


def test_invalid_query_does_not_add_exposure(setup_engines):
    budget, exposure, records = setup_engines

    with pytest.raises(ValueError):
        execute_protected_query(
            records=records,
            query_type="invalid_query",
            variant_id="rs123",
            budget=budget,
            participant_id="participant-001",
            requester_id="researcher-001",
            project_id="project-001",
            purpose="research",
            consent_id="consent-001",
            cost=1,
            familial_exposure=exposure,
        )

    assert exposure.get_exposure("participant-001") == 0
    assert exposure.get_exposure("participant-002") == 0
