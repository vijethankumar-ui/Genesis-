
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

from concurrent.futures import ThreadPoolExecutor


def test_concurrent_requests_cannot_exceed_budget(tmp_path):
    budget = DisclosureBudget(
        db_path=tmp_path / "concurrent.db",
        default_limit=3,
    )

    def attempt_query():
        try:
            consume_one(budget)
            return "allowed"
        except PermissionError:
            return "rejected"

    # Simulate 12 requests trying to use a budget of only 3.
    with ThreadPoolExecutor(max_workers=12) as executor:
        results = list(executor.map(
            lambda _: attempt_query(),
            range(12),
        ))

    assert results.count("allowed") == 3
    assert results.count("rejected") == 9

    status = budget.get_status(
        "sample-001",
        "researcher-001",
        "project-001",
        "approved_research",
        "consent-001",
    )
    assert status["used"] == 3
    assert status["remaining"] == 0


@pytest.mark.parametrize(
    "changed_scope",
    [
        {"requester_id": "researcher-002"},
        {"project_id": "project-002"},
        {"purpose": "different_purpose"},
        {"consent_id": "consent-002"},
    ],
)
def test_other_access_scopes_have_separate_budgets(
    budget, changed_scope
):
    consume_one(budget)

    # A different scope must have its own initial allowance.
    status = budget.get_status(
        participant_id="sample-001",
        requester_id=changed_scope.get(
            "requester_id", "researcher-001"
        ),
        project_id=changed_scope.get("project_id", "project-001"),
        purpose=changed_scope.get("purpose", "approved_research"),
        consent_id=changed_scope.get("consent_id", "consent-001"),
    )

    assert status["used"] == 0
    assert status["remaining"] == 3
