
import pytest
from fastapi.testclient import TestClient

import app.main as main
from privacy.disclosure_budget import DisclosureBudget
from privacy.identity_registry import IdentityRegistry


@pytest.fixture
def api_setup(tmp_path, monkeypatch):
    identity_db = tmp_path / "identities.db"
    budget_db = tmp_path / "budgets.db"
    vcf_path = tmp_path / "test.vcf.gz"
    vcf_path.touch()

    registry = IdentityRegistry(db_path=identity_db)
    registry.register("researcher-a", "group-001")
    registry.register("researcher-b", "group-001")

    budget = DisclosureBudget(
        db_path=budget_db,
        default_limit=2,
        identity_registry=registry,
    )

    monkeypatch.setattr(main, "VCF_PATH", vcf_path)
    monkeypatch.setattr(main, "get_identity_registry", lambda: registry)
    monkeypatch.setattr(main, "get_budget", lambda: budget)

    records = [{
        "chromosome": "22",
        "position": 16050213,
        "variant_id": "rs123",
        "reference": "C",
        "alternate": "T",
        "genotypes": {"sample-001": "0/1"},
    }]

    monkeypatch.setattr(
        main,
        "iter_variant_records",
        lambda *args, **kwargs: iter(records),
    )

    return TestClient(main.app), budget


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
    client, budget = api_setup

    first = client.post("/query", json=make_request("researcher-a"))
    second = client.post("/query", json=make_request("researcher-b"))
    third = client.post("/query", json=make_request("researcher-a"))

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
    client, _ = api_setup

    def fail_if_called(*args, **kwargs):
        pytest.fail("Dataset must not be read for unknown researchers")

    monkeypatch.setattr(main, "iter_variant_records", fail_if_called)

    response = client.post(
        "/query",
        json=make_request("unknown-researcher"),
    )

    assert response.status_code == 403
    assert "not registered" in response.json()["detail"].lower()
