import json

import pytest
from fastapi.testclient import TestClient

import app.main as main
from genesis_plugin.crypto_vault import StorageVault
from genesis_plugin.crypto_vault.keys import generate_dev_keys
from privacy.disclosure_budget import DisclosureBudget
from privacy.familial_exposure import FamilialExposure
from privacy.identity_registry import IdentityRegistry
from privacy.vault_repository import VaultRepository


@pytest.fixture
def real_vault_api(tmp_path, monkeypatch):
    # Generate isolated development keys and an isolated vault.
    key_dir = tmp_path / "keys"
    generate_dev_keys(key_dir)

    vault_dir = tmp_path / "vault"
    monkeypatch.setenv("GENESIS_VAULT_DIR", str(vault_dir))
    monkeypatch.setenv("GENESIS_MASTER_KEY_FILE", str(key_dir / "master.key"))
    monkeypatch.setenv(
        "GENESIS_SIGNING_KEY_FILE",
        str(key_dir / "ed25519-private.pem"),
    )
    monkeypatch.setenv(
        "GENESIS_TRUSTED_PUBLIC_KEY_FILE",
        str(key_dir / "ed25519-public.pem"),
    )

    vault = StorageVault.from_env()
    repository = VaultRepository(
        vault=vault,
        index_path=tmp_path / "variant_index.db",
    )

    # Use synthetic data only.
    record = {
        "chromosome": "22",
        "position": 16050213,
        "variant_id": "rs-test-001",
        "reference": "C",
        "alternate": "T",
        "genotypes": {"sample-test-001": "0/1"},
    }
    repository.store_record(record)

    registry = IdentityRegistry(db_path=tmp_path / "identities.db")
    registry.register("researcher-test", "group-test")

    budget = DisclosureBudget(
        db_path=tmp_path / "budget.db",
        default_limit=2,
        identity_registry=registry,
    )
    exposure = FamilialExposure(db_path=tmp_path / "exposure.db")

    monkeypatch.setattr(
        main, "VAULT_INDEX_PATH", tmp_path / "variant_index.db"
    )
    monkeypatch.setattr(main, "get_identity_registry", lambda: registry)
    monkeypatch.setattr(main, "get_budget", lambda: budget)
    monkeypatch.setattr(main, "get_familial_exposure", lambda: exposure)
    monkeypatch.setattr(main, "get_vault_repository", lambda: repository)

    return TestClient(main.app), budget, exposure, repository


def request_payload(requester_id="researcher-test"):
    return {
        "participant_id": "participant-test-001",
        "requester_id": requester_id,
        "project_id": "project-test-001",
        "purpose": "approved_research",
        "consent_id": "consent-test-001",
        "query_type": "variant_presence",
        "variant_id": "rs-test-001",
        "sample_id": "sample-test-001",
    }


def test_api_query_uses_real_encrypted_vault(real_vault_api):
    client, budget, exposure, repository = real_vault_api

    # Confirm the record is actually retrievable from the real vault.
    records = repository.get_variant_records("rs-test-001")
    assert len(records) == 1
    assert records[0]["genotypes"]["sample-test-001"] == "0/1"

    response = client.post("/query", json=request_payload())

    assert response.status_code == 200
    assert response.json() == {
        "query_type": "variant_presence",
        "variant_id": "rs-test-001",
        "result": True,
    }

    status = budget.get_status(
        "participant-test-001",
        "researcher-test",
        "project-test-001",
        "approved_research",
        "consent-test-001",
    )
    assert status["used"] == 1
    assert exposure.get_exposure("participant-test-001") == 1


def test_unknown_researcher_is_rejected_before_vault_access(
    real_vault_api, monkeypatch
):
    client, _, exposure, _ = real_vault_api

    def fail_if_called():
        pytest.fail("Vault repository accessed for an unknown researcher")

    monkeypatch.setattr(main, "get_vault_repository", fail_if_called)

    response = client.post(
        "/query",
        json=request_payload("unknown-researcher"),
    )

    assert response.status_code == 403
    assert exposure.get_exposure("participant-test-001") == 0
