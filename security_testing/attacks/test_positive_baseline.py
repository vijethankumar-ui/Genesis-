"""Positive (functional) baseline.

A legitimate, fully-authorized query MUST succeed. Without this, a system that
simply rejects everything would look 'secure' while being useless. Every attack
test below is only meaningful because this baseline passes.
"""

from security_testing import lab


def test_legitimate_query_succeeds(client):
    participant = "participant-P1"
    requester = "researcher-alice"
    purpose = "cancer_research"
    role = "researcher"
    variant = "rsBASE0001"
    sample = "SAMPLE-A"

    # Stage 1 - prepare a valid participant, researcher, record and consent.
    lab.register_identity(requester, "canonical-alice")
    lab.seed_variant_record(variant, {sample: "1|0"})  # carries an alternate allele
    policy = lab.create_consent(participant, purpose, role)

    # Stage 2 - execute the legitimate request.
    resp = lab.query(
        client,
        participant_id=participant,
        requester_id=requester,
        project_id="proj-baseline",
        purpose=purpose,
        consent_id=policy.policy_id,
        variant_id=variant,
        query_type="variant_presence",
        sample_id=sample,
        role=role,
    )

    # Stage 3 - verify the answer and that exactly one unit of budget was spent.
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"] is True

    status = lab.budget_status(
        participant, requester, "proj-baseline", purpose, str(policy.policy_id)
    )
    assert status["used"] == 1
    assert status["remaining"] == status["limit"] - 1
