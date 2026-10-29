
import pytest
from fastapi.testclient import TestClient

import app.main as main
from privacy.familial_exposure import FamilialExposure


@pytest.fixture
def client_with_test_database(tmp_path, monkeypatch):
    tracker = FamilialExposure(
        db_path=tmp_path / "familial_exposure.db"
    )
    monkeypatch.setattr(main, "get_familial_exposure", lambda: tracker)

    return TestClient(main.app)


def test_register_family_relationship(client_with_test_database):
    response = client_with_test_database.post(
        "/family/relationships",
        json={
            "participant_id": "participant-001",
            "relative_id": "participant-002",
            "relationship": "sibling",
        },
    )

    assert response.status_code == 200
    assert response.json()["status"] == "registered"


def test_family_relationship_is_visible_both_directions(
    client_with_test_database,
):
    client = client_with_test_database

    response = client.post(
        "/family/relationships",
        json={
            "participant_id": "participant-001",
            "relative_id": "participant-002",
            "relationship": "sibling",
        },
    )
    assert response.status_code == 200

    first = client.get("/family/exposure/participant-001")
    second = client.get("/family/exposure/participant-002")

    assert first.status_code == 200
    assert second.status_code == 200
    assert "participant-002" in first.json()["linked_relatives"]
    assert "participant-001" in second.json()["linked_relatives"]


def test_self_relationship_returns_bad_request(client_with_test_database):
    response = client_with_test_database.post(
        "/family/relationships",
        json={
            "participant_id": "participant-001",
            "relative_id": "participant-001",
            "relationship": "sibling",
        },
    )

    assert response.status_code == 400
