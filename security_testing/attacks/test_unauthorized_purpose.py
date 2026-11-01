"""Attack 1 - Unauthorized-purpose access.

A researcher holds consent for ``cancer_research`` but submits a query declaring
``ancestry_research``. A valid account must NOT grant access for every purpose.

Expected secure behaviour:
  - the consent gate finds no ACTIVE policy matching the declared purpose,
  - the request is rejected (403) before the vault is touched,
  - no disclosure budget is consumed for the denied purpose,
  - the denial is recorded in the governance audit log.
"""

from security_testing import lab


def test_unauthorized_purpose_is_denied(client):
    participant = "participant-P2"
    requester = "researcher-bob"
    role = "researcher"
    variant = "rsAUTH0002"
    sample = "SAMPLE-B"

    # Stage 1 - consent is granted ONLY for cancer_research.
    lab.register_identity(requester, "canonical-bob")
    lab.seed_variant_record(variant, {sample: "1|1"})
    policy = lab.create_consent(participant, "cancer_research", role)

    # Stage 2 - attacker reuses the same valid account for a different purpose.
    resp = lab.query(
        client,
        participant_id=participant,
        requester_id=requester,
        project_id="proj-1",
        purpose="ancestry_research",  # NOT consented
        consent_id=policy.policy_id,
        variant_id=variant,
        query_type="variant_presence",
        sample_id=sample,
        role=role,
    )

    # Stage 3 - verify rejection, no budget side effect, and an audit record.
    assert resp.status_code == 403, resp.text

    status = lab.budget_status(
        participant, requester, "proj-1", "ancestry_research", str(policy.policy_id)
    )
    assert status["used"] == 0, "denied request must not consume budget"

    decisions = [row[2] for row in lab.latest_audit_events(limit=10)]
    assert "DENY" in decisions, "denial should be recorded in the audit log"
