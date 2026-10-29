
import pytest

from privacy.disclosure_budget import DisclosureBudget


@pytest.fixture
def budget(tmp_path):
    return DisclosureBudget(
        db_path=tmp_path / "budget.db",
        default_limit=3,
    )


def consume_one(budget, **overrides):
    scope = {
        "participant_id": "sample-001",
        "requester_id": "researcher-001",
        "project_id": "project-001",
        "purpose": "approved_research",
        "consent_id": "consent-001",
    }
    scope.update(overrides)
    return budget.consume(**scope)


def test_budget_starts_at_zero(budget):
    status = budget.get_status(
        "sample-001",
        "researcher-001",
        "project-001",
        "approved_research",
        "consent-001",
    )

    assert status == {"limit": 3, "used": 0, "remaining": 3}


def test_budget_decreases_after_query(budget):
    status = consume_one(budget)

    assert status == {"limit": 3, "used": 1, "remaining": 2}


def test_budget_exhaustion_rejects_request(budget):
    consume_one(budget)
    consume_one(budget)
    consume_one(budget)

    with pytest.raises(PermissionError, match="exhausted"):
        consume_one(budget)


def test_different_participant_has_separate_budget(budget):
    consume_one(budget, participant_id="sample-002")

    status = budget.get_status(
        "sample-001",
        "researcher-001",
        "project-001",
        "approved_research",
        "consent-001",
    )

    assert status["used"] == 0


def test_budget_survives_reinitialization(tmp_path):
    db_path = tmp_path / "persistent.db"

    first = DisclosureBudget(db_path=db_path, default_limit=3)
    consume_one(first)

    second = DisclosureBudget(db_path=db_path, default_limit=3)

    status = second.get_status(
        "sample-001",
        "researcher-001",
        "project-001",
        "approved_research",
        "consent-001",
    )

    assert status["used"] == 1
    assert status["remaining"] == 2


def test_invalid_cost_is_rejected(budget):
    with pytest.raises(ValueError, match="cost"):
        consume_one(budget, cost=0)
