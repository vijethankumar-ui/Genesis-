
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
    assert "participant-002" in exposure.get_relatives(
        "participant-001"
    )
    assert "participant-001" in exposure.get_relatives(
        "participant-002"
    )


def test_disclosure_updates_participant_and_direct_relatives(exposure):
    totals = exposure.record_disclosure("participant-001", cost=2)

    assert totals == {"participant-001": 2}
    assert exposure.get_exposure("participant-001") == 2
    assert exposure.get_exposure("participant-002") == 0
    assert exposure.get_exposure("participant-003") == 0

    summary = exposure.get_exposure_summary("participant-001")

    assert summary["direct_exposure_units"] == 2
    assert set(summary["linked_relatives"]) == {
        "participant-002",
        "participant-003",
    }
    assert summary["potential_familial_exposure_units"] == 0


def test_repeated_disclosures_accumulate(exposure):
    exposure.record_disclosure("participant-001")
    exposure.record_disclosure("participant-001", cost=2)

    assert exposure.get_exposure("participant-001") == 3
    assert exposure.get_exposure("participant-002") == 0

    exposure.record_disclosure("participant-002", cost=2)

    summary = exposure.get_exposure_summary("participant-001")
    assert summary["potential_familial_exposure_units"] == 2


def test_unrelated_participant_is_unaffected(exposure):
    exposure.record_disclosure("participant-001", cost=2)

    assert exposure.get_exposure("participant-004") == 0


def test_self_relationship_is_rejected(exposure):
    with pytest.raises(ValueError):
        exposure.register_relationship(
            "participant-001",
            "participant-001",
            "self",
        )


def test_duplicate_relationship_is_rejected(exposure):
    with pytest.raises(ValueError):
        exposure.register_relationship(
            "participant-001",
            "participant-002",
            "sibling",
        )


@pytest.mark.parametrize("cost", [0, -1, True, 1.5, "2", None])
def test_invalid_cost_is_rejected(exposure, cost):
    with pytest.raises(ValueError):
        exposure.record_disclosure("participant-001", cost=cost)
