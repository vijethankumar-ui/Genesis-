
import pytest

from privacy.familial_exposure import FamilialExposure


@pytest.fixture
def exposure(tmp_path):
    tracker = FamilialExposure(
        db_path=tmp_path / "familial_exposure.db"
    )
    tracker.register_relationship(
        "participant-001", "participant-002", "sibling"
    )
    tracker.register_relationship(
        "participant-001", "participant-003", "parent"
    )
    return tracker


def test_relationships_are_found_in_both_directions(exposure):
    assert exposure.get_relatives("participant-001") == [
        "participant-002",
        "participant-003",
    ]
    assert exposure.get_relatives("participant-002") == [
        "participant-001",
    ]


def test_disclosure_updates_participant_and_direct_relatives(exposure):
    totals = exposure.record_disclosure("participant-001", cost=2)

    assert totals == {
        "participant-001": 2,
        "participant-002": 2,
        "participant-003": 2,
    }


def test_repeated_disclosures_accumulate(exposure):
    exposure.record_disclosure("participant-001")
    exposure.record_disclosure("participant-001", cost=2)

    assert exposure.get_exposure("participant-001") == 3
    assert exposure.get_exposure("participant-002") == 3
    assert exposure.get_exposure("participant-003") == 3


def test_unrelated_participant_is_unaffected(exposure):
    exposure.record_disclosure("participant-001")

    assert exposure.get_exposure("unrelated-001") == 0


def test_self_relationship_is_rejected(exposure):
    with pytest.raises(ValueError, match="own relative"):
        exposure.register_relationship(
            "participant-004",
            "participant-004",
            "sibling",
        )


def test_duplicate_relationship_is_rejected(exposure):
    with pytest.raises(ValueError, match="already registered"):
        exposure.register_relationship(
            "participant-001",
            "participant-002",
            "sibling",
        )


def test_invalid_cost_is_rejected(exposure):
    with pytest.raises(ValueError, match="cost"):
        exposure.record_disclosure("participant-001", cost=0)
