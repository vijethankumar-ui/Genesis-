
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.main import app
from app.core.config import (
    AUTH_DEMO_USERNAME,
    AUTH_DEMO_PASSWORD,
    AUTH_DEMO_ROLE,
)
from app.services.consent_service import create_consent_policy
from app.models.consent import ConsentPolicyCreate


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
