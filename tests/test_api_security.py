
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.core.config import (
    AUTH_DEMO_USERNAME,
    AUTH_DEMO_PASSWORD,
    AUTH_DEMO_ROLE,
    AUTH_DEMO_SUBJECT_ID,
)
from app.services.consent_service import create_consent_policy
from app.models.consent import ConsentPolicyCreate

from unittest.mock import Mock

import app.main as main_module


client = TestClient(app)


def get_valid_token():
    response = client.post(
        "/auth/login",
        json={
            "username": AUTH_DEMO_USERNAME,
            "password": AUTH_DEMO_PASSWORD,
        },
    )

    assert response.status_code == 200
    return response.json()["access_token"]


def test_valid_login():
    response = client.post(
        "/auth/login",
        json={
            "username": AUTH_DEMO_USERNAME,
            "password": AUTH_DEMO_PASSWORD,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["token_type"] == "bearer"
    assert isinstance(data["access_token"], str)
    assert data["expires_in"] > 0


def test_invalid_login():
    response = client.post(
        "/auth/login",
        json={
            "username": AUTH_DEMO_USERNAME,
            "password": "incorrect-test-password",
        },
    )

    assert response.status_code == 401


def test_authorization_without_token():
    response = client.post(
        "/authorize",
        json={
            "subject_id": "GENESIS-API-TEST-001",
            "data_scope": "synthetic_health_summary",
            "purpose": "research",
            "recipient_role": AUTH_DEMO_ROLE,
        },
    )

    assert response.status_code == 401


def test_authorization_with_invalid_token():
    response = client.post(
        "/authorize",
        headers={
            "Authorization": "Bearer invalid.test.token",
        },
        json={
            "subject_id": "GENESIS-API-TEST-001",
            "data_scope": "synthetic_health_summary",
            "purpose": "research",
            "recipient_role": AUTH_DEMO_ROLE,
        },
    )

    assert response.status_code == 401


def test_authorization_with_wrong_role():
    token = get_valid_token()

    response = client.post(
        "/authorize",
        headers={
            "Authorization": f"Bearer {token}",
        },
        json={
            "subject_id": "GENESIS-API-TEST-001",
            "data_scope": "synthetic_health_summary",
            "purpose": "research",
            "recipient_role": "unauthorized-test-role",
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"


def test_authorization_with_valid_token_and_consent():
    policy = create_consent_policy(
        ConsentPolicyCreate(
            subject_id="GENESIS-API-TEST-001",
            data_scope="synthetic_health_summary",
            approved_purpose="research",
            recipient_role=AUTH_DEMO_ROLE,
            expiry_date=datetime.now(timezone.utc)
            + timedelta(days=1),
        )
    )

    token = get_valid_token()

    response = client.post(
        "/authorize",
        headers={
            "Authorization": f"Bearer {token}",
        },
        json={
            "subject_id": policy.subject_id,
            "data_scope": policy.data_scope,
            "purpose": policy.approved_purpose,
            "recipient_role": policy.recipient_role,
        },
    )

    assert response.status_code == 200
    assert response.json()["decision"] == "PERMIT"
    assert response.json()["policy_id"] == str(policy.policy_id)

def test_query_denied_without_consent_before_vault_access(monkeypatch):
    token = get_valid_token()

    identity_registry = Mock()
    identity_registry.resolve.return_value = "canonical-identity"

    vault_accessed = False

    def fail_if_vault_accessed():
        nonlocal vault_accessed
        vault_accessed = True
        raise AssertionError("Vault must not be accessed when consent is denied")

    monkeypatch.setattr(
        main_module,
        "get_identity_registry",
        lambda: identity_registry,
    )
    monkeypatch.setattr(
        main_module,
        "get_vault_repository",
        fail_if_vault_accessed,
    )

    response = client.post(
        "/query",
        headers={
            "Authorization": f"Bearer {token}",
        },
        json={
            "participant_id": "GENESIS-QUERY-TEST-001",
            "requester_id": AUTH_DEMO_SUBJECT_ID,
            "project_id": "project-001",
            "purpose": "unapproved-purpose",
            "consent_id": "missing-consent",
            "query_type": "variant_presence",
            "variant_id": "rs123",
            "sample_id": "sample-001",
        },
    )

    assert response.status_code == 403
    assert "consent" in response.json()["detail"].lower()
    assert vault_accessed is False

def test_query_with_valid_consent_reaches_vault_and_query(monkeypatch):
    participant_id = "GENESIS-QUERY-TEST-002"
    purpose = "approved_genomic_research"

    policy = create_consent_policy(
        ConsentPolicyCreate(
            subject_id=participant_id,
            data_scope=main_module.GENOMIC_DATA_SCOPE,
            approved_purpose=purpose,
            recipient_role=AUTH_DEMO_ROLE,
            expiry_date=datetime.now(timezone.utc)
            + timedelta(days=1),
        )
    )

    token = get_valid_token()

    identity_registry = Mock()
    identity_registry.resolve.return_value = "canonical-identity"

    vault_repository = Mock()
    vault_repository.get_variant_records.return_value = [
        {
            "variant_id": "rs123",
            "sample_id": "sample-001",
            "genotype": "0/1",
        }
    ]

    protected_query = Mock(return_value=True)

    monkeypatch.setattr(
        main_module,
        "get_identity_registry",
        lambda: identity_registry,
    )
    monkeypatch.setattr(
        main_module,
        "get_vault_repository",
        lambda: vault_repository,
    )

    vault_index = Mock()
    vault_index.is_file.return_value = True

    monkeypatch.setattr(
        main_module,
        "VAULT_INDEX_PATH",
        vault_index,
    )

    monkeypatch.setattr(
        main_module,
        "execute_protected_query",
        protected_query,
    )

    response = client.post(
        "/query",
        headers={
            "Authorization": f"Bearer {token}",
        },
        json={
            "participant_id": participant_id,
            "requester_id": AUTH_DEMO_SUBJECT_ID,
            "project_id": "project-001",
            "purpose": purpose,
            "consent_id": str(policy.policy_id),
            "query_type": "variant_presence",
            "variant_id": "rs123",
            "sample_id": "sample-001",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "query_type": "variant_presence",
        "variant_id": "rs123",
        "result": True,
    }

    identity_registry.resolve.assert_called_once_with(AUTH_DEMO_SUBJECT_ID)
    vault_repository.get_variant_records.assert_called_once_with("rs123")
    protected_query.assert_called_once()
def make_query_payload(participant_id, purpose, consent_id):
    return {
        "participant_id": participant_id,
        "requester_id": AUTH_DEMO_SUBJECT_ID,
        "project_id": "project-001",
        "purpose": purpose,
        "consent_id": consent_id,
        "query_type": "variant_presence",
        "variant_id": "rs123",
        "sample_id": "sample-001",
    }


def mock_query_dependencies(monkeypatch):
    identity_registry = Mock()
    identity_registry.resolve.return_value = "canonical-identity"

    vault_repository = Mock()
    vault_repository.get_variant_records.side_effect = AssertionError(
        "Vault must not be accessed for a denied request"
    )

    monkeypatch.setattr(
        main_module,
        "get_identity_registry",
        lambda: identity_registry,
    )
    monkeypatch.setattr(
        main_module,
        "get_vault_repository",
        lambda: vault_repository,
    )

    vault_index = Mock()
    vault_index.is_file.return_value = True

    monkeypatch.setattr(
        main_module,
        "VAULT_INDEX_PATH",
        vault_index,
    )

def test_query_denied_for_wrong_purpose(monkeypatch):
    participant_id = "GENESIS-QUERY-TEST-003"
    approved_purpose = "approved_genomic_research"

    policy = create_consent_policy(
        ConsentPolicyCreate(
            subject_id=participant_id,
            data_scope=main_module.GENOMIC_DATA_SCOPE,
            approved_purpose=approved_purpose,
            recipient_role=AUTH_DEMO_ROLE,
            expiry_date=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )

    mock_query_dependencies(monkeypatch)

    response = client.post(
        "/query",
        headers={"Authorization": f"Bearer {get_valid_token()}"},
        json=make_query_payload(
            participant_id,
            "different_purpose",
            str(policy.policy_id),
        ),
    )

    assert response.status_code == 403

def test_query_denied_for_expired_consent(monkeypatch):
    participant_id = "GENESIS-QUERY-TEST-004"
    purpose = "approved_genomic_research"

    policy = create_consent_policy(
        ConsentPolicyCreate(
            subject_id=participant_id,
            data_scope=main_module.GENOMIC_DATA_SCOPE,
            approved_purpose=purpose,
            recipient_role=AUTH_DEMO_ROLE,
            expiry_date=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )

    from app.core.config import (
        DB_HOST,
        DB_PORT,
        DB_NAME,
        DB_USER,
        DB_PASSWORD,
    )
    import psycopg

    with psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE consent_policies
                SET expiry_date = CURRENT_TIMESTAMP - INTERVAL '1 day'
                WHERE policy_id = %s
                """,
                (policy.policy_id,),
            )

    mock_query_dependencies(monkeypatch)

    response = client.post(
        "/query",
        headers={"Authorization": f"Bearer {get_valid_token()}"},
        json=make_query_payload(
            participant_id,
            purpose,
            str(policy.policy_id),
        ),
    )

    assert response.status_code == 403

def test_query_denied_for_revoked_consent(monkeypatch):
    participant_id = "GENESIS-QUERY-TEST-005"
    purpose = "approved_genomic_research"

    policy = create_consent_policy(
        ConsentPolicyCreate(
            subject_id=participant_id,
            data_scope=main_module.GENOMIC_DATA_SCOPE,
            approved_purpose=purpose,
            recipient_role=AUTH_DEMO_ROLE,
            expiry_date=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )

    from app.services.consent_service import revoke_consent_policy

    revoke_consent_policy(
        policy.policy_id,
        actor_id=AUTH_DEMO_SUBJECT_ID,
    )

    mock_query_dependencies(monkeypatch)

    response = client.post(
        "/query",
        headers={"Authorization": f"Bearer {get_valid_token()}"},
        json=make_query_payload(
            participant_id,
            purpose,
            str(policy.policy_id),
        ),
    )

    assert response.status_code == 403

def test_query_denied_for_mismatched_consent_id(monkeypatch):
    participant_id = "GENESIS-QUERY-TEST-006"
    purpose = "approved_genomic_research"

    policy = create_consent_policy(
        ConsentPolicyCreate(
            subject_id=participant_id,
            data_scope=main_module.GENOMIC_DATA_SCOPE,
            approved_purpose=purpose,
            recipient_role=AUTH_DEMO_ROLE,
            expiry_date=datetime.now(timezone.utc) + timedelta(days=1),
        )
    )

    mock_query_dependencies(monkeypatch)

    response = client.post(
        "/query",
        headers={"Authorization": f"Bearer {get_valid_token()}"},
        json=make_query_payload(
            participant_id,
            purpose,
            "00000000-0000-0000-0000-000000000000",
        ),
    )

    assert response.status_code == 403