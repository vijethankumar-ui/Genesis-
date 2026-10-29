
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
