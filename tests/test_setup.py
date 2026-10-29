
from datetime import datetime, timedelta, timezone

from app.models.consent import ConsentPolicyCreate
from app.services.consent_service import (
    create_consent_policy,
    get_consent_policy,
)


def test_create_and_retrieve_consent_policy():
    policy_data = ConsentPolicyCreate(
        subject_id="GENESIS-TEST-001",
        data_scope="synthetic_health_summary",
        approved_purpose="research",
        recipient_role="researcher",
        expiry_date=datetime.now(timezone.utc) + timedelta(days=30),
    )

    created = create_consent_policy(policy_data)
    retrieved = get_consent_policy(created.policy_id)

    assert retrieved is not None
    assert retrieved.policy_id == created.policy_id
    assert retrieved.subject_id == "GENESIS-TEST-001"
    assert retrieved.status == "ACTIVE"
