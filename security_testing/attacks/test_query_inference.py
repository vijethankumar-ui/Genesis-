"""Attack 3 - Repeated-query inference / disclosure-budget enforcement.

Individually harmless queries, combined, can reveal sensitive genetic
information. The disclosure budget must cap how much a scope can learn.

Verified here:
  A. Within one scope, the budget (default 10) is enforced: the 11th query is
     rejected and `used` never exceeds the limit.
  B. A new session (fresh token) does NOT reset the allowance.

FINDING probe (C): `project_id` is supplied by the caller and is NOT validated
against the consent policy, while it IS part of the budget key. So the same
researcher, same participant, same consent and purpose can obtain a fresh budget
simply by changing `project_id`. If C passes, the budget is resettable and the
inference cap is bypassable.
"""

from security_testing import lab

LIMIT = 10


def _setup(client):
    participant = "participant-INF"
    requester = "researcher-inf"
    role = "researcher"
    variant = "rsINFER01"
    sample = "SAMPLE-I"
    lab.register_identity(requester, "canonical-inf")
    lab.seed_variant_record(variant, {sample: "1|0"})
    policy = lab.create_consent(participant, "cancer_research", role)
    return participant, requester, role, variant, sample, policy


def _fire(client, participant, requester, role, variant, sample, policy, project, token=None):
    return lab.query(
        client,
        participant_id=participant,
        requester_id=requester,
        project_id=project,
        purpose="cancer_research",
        consent_id=policy.policy_id,
        variant_id=variant,
        sample_id=sample,
        role=role,
        token=token,
    )


def test_budget_caps_repeated_queries(client):
    participant, requester, role, variant, sample, policy = _setup(client)
    project = "proj-A"

    # A. Exactly LIMIT queries succeed; the next is rejected.
    for i in range(LIMIT):
        resp = _fire(client, participant, requester, role, variant, sample, policy, project)
        assert resp.status_code == 200, f"query {i + 1} should succeed: {resp.text}"

    over = _fire(client, participant, requester, role, variant, sample, policy, project)
    assert over.status_code == 429, "over-budget query must be rejected"

    status = lab.budget_status(participant, requester, project, "cancer_research", str(policy.policy_id))
    assert status["used"] == LIMIT
    assert status["remaining"] == 0


def test_new_session_does_not_reset_budget(client):
    participant, requester, role, variant, sample, policy = _setup(client)
    project = "proj-B"

    for _ in range(LIMIT):
        assert _fire(client, participant, requester, role, variant, sample, policy, project).status_code == 200

    # B. A brand-new token (new session) for the same identity/scope.
    new_token = lab.make_auth_token(requester, role)
    resp = _fire(client, participant, requester, role, variant, sample, policy, project, token=new_token)
    assert resp.status_code == 429, "a new session must not restart the allowance"


def test_project_id_resets_budget_FINDING(client):
    """FINDING: budget is bypassable by varying the caller-controlled project_id."""
    participant, requester, role, variant, sample, policy = _setup(client)

    # Exhaust the budget under one project_id.
    for _ in range(LIMIT):
        assert _fire(client, participant, requester, role, variant, sample, policy, "proj-X").status_code == 200
    assert _fire(client, participant, requester, role, variant, sample, policy, "proj-X").status_code == 429

    # Same participant / consent / purpose, only a different project_id.
    bypass = _fire(client, participant, requester, role, variant, sample, policy, "proj-Y-bypass")

    # The attack SUCCEEDS -> this documents a real gap, not a defended case.
    assert bypass.status_code == 200, (
        "If this fails the gap was closed; update the finding."
    )
    fresh = lab.budget_status(participant, requester, "proj-Y-bypass", "cancer_research", str(policy.policy_id))
    assert fresh["used"] == 1 and fresh["remaining"] == LIMIT - 1
