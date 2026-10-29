
import pytest
from fastapi.testclient import TestClient

import app.main as main
from privacy.disclosure_budget import DisclosureBudget
from privacy.familial_exposure import FamilialExposure
from privacy.identity_registry import IdentityRegistry


@pytest.fixture
def api_setup(tmp_path, monkeypatch):
    identity_db = tmp_path / "identities.db"
    budget_db = tmp_path / "budgets.db"
    familial_db = tmp_path / "familial_exposure.db"
    vault_index_path = tmp_path / "variant_index.db"
    vault_index_path.touch()


    registry = IdentityRegistry(db_path=identity_db)
    registry.register("researcher-a", "group-001")
    registry.register("researcher-b", "group-001")

    budget = DisclosureBudget(
        db_path=budget_db,
        default_limit=2,
        identity_registry=registry,
    )

    exposure = FamilialExposure(db_path=familial_db)

    records = [
        {
            "chromosome": "22",
            "position": 16050213,
            "variant_id": "rs123",
            "reference": "C",
            "alternate": "T",
            "genotypes": {"sample-001": "0/1"},
        }
    ]

    class FakeVaultRepository:
        def get_variant_records(self, variant_id):
            return [
                record
                for record in records
                if record.get("variant_id") == variant_id
            ]

    repository = FakeVaultRepository()

    monkeypatch.setattr(
        main,
        "VAULT_INDEX_PATH",
        vault_index_path,
        raising=False,
    )
    monkeypatch.setattr(
        main,
        "get_identity_registry",
        lambda: registry,
    )
    monkeypatch.setattr(main, "get_budget", lambda: budget)
    monkeypatch.setattr(
        main,
        "get_familial_exposure",
        lambda: exposure,
    )
    monkeypatch.setattr(
        main,
        "get_vault_repository",
        lambda: repository,
        raising=False,
    )

    return TestClient(main.app), budget, exposure


def make_request(requester_id):
    return {
        "participant_id": "participant-001",
        "requester_id": requester_id,
        "project_id": "project-001",
        "purpose": "approved_research",
        "consent_id": "consent-001",
        "query_type": "variant_presence",
        "variant_id": "rs123",
        "sample_id": "sample-001",
    }


def test_linked_accounts_share_budget_through_api(api_setup):
    client, budget, _ = api_setup

    first = client.post(
        "/query",
        json=make_request("researcher-a"),
    )
    second = client.post(
        "/query",
        json=make_request("researcher-b"),
    )
    third = client.post(
        "/query",
        json=make_request("researcher-a"),
    )

    assert first.status_code == 200
    assert first.json()["result"] is True

    assert second.status_code == 200
    assert second.json()["result"] is True

    assert third.status_code == 429
    assert "budget exhausted" in third.json()["detail"].lower()

    status = budget.get_status(
        "participant-001",
        "researcher-a",
        "project-001",
        "approved_research",
        "consent-001",
    )

    assert status["used"] == 2
    assert status["remaining"] == 0


def test_unknown_researcher_is_rejected_before_data_access(
    api_setup, monkeypatch
):
    client, _, exposure = api_setup

    def fail_if_called():
        pytest.fail(
            "Vault repository must not be accessed for unknown researchers"
        )

    monkeypatch.setattr(
        main,
        "get_vault_repository",
        fail_if_called,
    )

    response = client.post(
        "/query",
        json=make_request("unknown-researcher"),
    )

    assert response.status_code == 403
    assert "not registered" in response.json()["detail"].lower()

    # Rejected requests must not record familial exposure.
    assert exposure.get_exposure("participant-001") == 0


def test_query_api_records_familial_exposure(api_setup):
    client, budget, exposure = api_setup

    response = client.post(
        "/query",
        json=make_request("researcher-a"),
    )

    assert response.status_code == 200
    assert response.json()["result"] is True

    status = budget.get_status(
        "participant-001",
        "researcher-a",
        "project-001",
        "approved_research",
        "consent-001",
    )

    assert status["used"] == 1
    assert status["remaining"] == 1
    assert exposure.get_exposure("participant-001") == 1

def test_invalid_query_does_not_consume_budget(api_setup):
    client, budget, exposure = api_setup
    request = make_request("researcher-a")
    request["query_type"] = "raw_records"

    response = client.post("/query", json=request)

    assert response.status_code == 422

    status = budget.get_status(
        "participant-001",
        "researcher-a",
        "project-001",
        "approved_research",
        "consent-001",
    )
    assert status["used"] == 0
    assert exposure.get_exposure("participant-001") == 0


def test_unknown_variant_does_not_consume_budget(api_setup):
    client, budget, exposure = api_setup
    request = make_request("researcher-a")
    request["variant_id"] = "rs-not-in-dataset"

    response = client.post("/query", json=request)

    assert response.status_code == 200
    assert response.json()["result"] is False

    status = budget.get_status(
        "participant-001",
        "researcher-a",
        "project-001",
        "approved_research",
        "consent-001",
    )
    assert status["used"] == 1
    assert exposure.get_exposure("participant-001") == 1


def test_vault_failure_does_not_consume_budget(api_setup, monkeypatch):
    client, budget, exposure = api_setup

    def fail_retrieval():
        raise RuntimeError("Simulated vault failure")

    monkeypatch.setattr(
        main,
        "get_vault_repository",
        fail_retrieval,
    )

    response = client.post(
        "/query",
        json=make_request("researcher-a"),
    )

    assert response.status_code == 503

    status = budget.get_status(
        "participant-001",
        "researcher-a",
        "project-001",
        "approved_research",
        "consent-001",
    )
    assert status["used"] == 0
    assert exposure.get_exposure("participant-001") == 0
