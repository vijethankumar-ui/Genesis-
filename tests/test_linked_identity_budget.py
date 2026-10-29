
from privacy.disclosure_budget import DisclosureBudget
from privacy.identity_registry import IdentityRegistry


def test_linked_accounts_share_disclosure_budget(tmp_path):
    registry = IdentityRegistry(
        db_path=tmp_path / "identities.db"
    )
    registry.register("researcher-a", "group-001")
    registry.register("researcher-b", "group-001")

    budget = DisclosureBudget(
        db_path=tmp_path / "budget.db",
        default_limit=2,
        identity_registry=registry,
    )

    first = budget.consume(
        participant_id="participant-001",
        requester_id="researcher-a",
        project_id="project-001",
        purpose="approved_research",
        consent_id="consent-001",
    )

    assert first == {"limit": 2, "used": 1, "remaining": 1}

    second = budget.consume(
        participant_id="participant-001",
        requester_id="researcher-b",
        project_id="project-001",
        purpose="approved_research",
        consent_id="consent-001",
    )

    assert second == {"limit": 2, "used": 2, "remaining": 0}


def test_unknown_identity_cannot_consume_budget(tmp_path):
    registry = IdentityRegistry(
        db_path=tmp_path / "identities.db"
    )
    budget = DisclosureBudget(
        db_path=tmp_path / "budget.db",
        identity_registry=registry,
    )

    try:
        budget.consume(
            participant_id="participant-001",
            requester_id="unknown-researcher",
            project_id="project-001",
            purpose="approved_research",
            consent_id="consent-001",
        )
    except PermissionError as exc:
        assert "not registered" in str(exc)
    else:
        raise AssertionError("Unregistered requester should be rejected")

def test_linked_account_cannot_bypass_exhausted_budget(tmp_path):
    registry = IdentityRegistry(
        db_path=tmp_path / "identities.db"
    )
    registry.register("researcher-a", "group-001")
    registry.register("researcher-b", "group-001")

    budget = DisclosureBudget(
        db_path=tmp_path / "budget.db",
        default_limit=2,
        identity_registry=registry,
    )

    # Consume the entire shared budget using researcher-a.
    for _ in range(2):
        budget.consume(
            participant_id="participant-001",
            requester_id="researcher-a",
            project_id="project-001",
            purpose="approved_research",
            consent_id="consent-001",
        )

    # Switching to the linked account must not grant more budget.
    try:
        budget.consume(
            participant_id="participant-001",
            requester_id="researcher-b",
            project_id="project-001",
            purpose="approved_research",
            consent_id="consent-001",
        )
    except PermissionError as exc:
        assert "budget exhausted" in str(exc).lower()
    else:
        raise AssertionError(
            "A linked account must not bypass the exhausted budget"
        )

    status = budget.get_status(
        participant_id="participant-001",
        requester_id="researcher-b",
        project_id="project-001",
        purpose="approved_research",
        consent_id="consent-001",
    )

    assert status["limit"] == 2
    assert status["used"] == 2
    assert status["remaining"] == 0
