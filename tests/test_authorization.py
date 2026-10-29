
from datetime import datetime, timedelta, timezone

from app.models.authorization import AccessRequest
from app.models.consent import ConsentPolicyCreate
from app.services.authorization_service import authorize_access
from app.services.consent_service import create_consent_policy


def test_matching_consent_is_permitted():
    subject_id = "GENESIS-AUTH-TEST-001"

    policy = create_consent_policy(
        ConsentPolicyCreate(
            subject_id=subject_id,
            data_scope="synthetic_health_summary",
            approved_purpose="research",
            recipient_role="researcher",
            expiry_date=datetime.now(timezone.utc) + timedelta(days=30),
        )
    )

    request = AccessRequest(
        subject_id=subject_id,
        data_scope="synthetic_health_summary",
        purpose="research",
        recipient_role="researcher",
    )

    decision = authorize_access(request)

    assert decision.decision == "PERMIT"
    assert decision.policy_id == str(policy.policy_id)


def test_wrong_purpose_is_denied():
    request = AccessRequest(
        subject_id="GENESIS-AUTH-TEST-001",
        data_scope="synthetic_health_summary",
        purpose="marketing",
        recipient_role="researcher",
    )

    decision = authorize_access(request)

    assert decision.decision == "DENY"
    assert decision.policy_id is None


def test_wrong_recipient_role_is_denied():
    request = AccessRequest(
        subject_id="GENESIS-AUTH-TEST-001",
        data_scope="synthetic_health_summary",
        purpose="research",
        recipient_role="administrator",
    )

    decision = authorize_access(request)

    assert decision.decision == "DENY"
    assert decision.policy_id is None
