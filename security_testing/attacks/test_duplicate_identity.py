"""Attack 4 - Duplicate identity.

A researcher creates several accounts to get N x the permitted budget. The
budget resolves each account to a *canonical identity*, so accounts that are
LINKED share one allowance.

Verified here:
  A. Two accounts linked to the same canonical identity share a single budget;
     exhausting it on one account blocks the other. The budget is resistant to
     identity multiplication *when linking is applied*.

Documented boundary (B): the system cannot detect that two UNLINKED accounts
belong to the same human (per the brief, this must not be assumed). Without a
registry link, each account receives an independent budget. This is the exact
reason the identity-linking mechanism must be used - and why collusion (Attack
5) is a real gap.
"""

from security_testing import lab

LIMIT = 10


def _q(client, requester, participant, policy, project="proj-dup"):
    return lab.query(
        client,
        participant_id=participant,
        requester_id=requester,
        project_id=project,
        purpose="cancer_research",
        consent_id=policy.policy_id,
        variant_id="rsDUP0001",
        sample_id="SAMPLE-D",
        role="researcher",
    )


def test_linked_accounts_share_budget(client):
    participant = "participant-DUP"
    lab.seed_variant_record("rsDUP0001", {"SAMPLE-D": "1|0"})
    policy = lab.create_consent(participant, "cancer_research", "researcher")

    # Two accounts, same human -> linked to one canonical identity.
    lab.register_identity("dup-acct-1", "canonical-dup")
    lab.register_identity("dup-acct-2", "canonical-dup")

    # Account 1 exhausts the shared budget.
    for _ in range(LIMIT):
        assert _q(client, "dup-acct-1", participant, policy).status_code == 200

    # Account 2 (same canonical identity) is already out of budget.
    blocked = _q(client, "dup-acct-2", participant, policy)
    assert blocked.status_code == 429, "linked accounts must share one allowance"

    status = lab.budget_status(participant, "dup-acct-2", "proj-dup", "cancer_research", str(policy.policy_id))
    assert status["used"] == LIMIT, "combined disclosures must not exceed the single limit"


def test_unlinked_accounts_get_independent_budgets_BOUNDARY(client):
    """BOUNDARY: without a registry link, duplicate accounts are not detected."""
    participant = "participant-DUP2"
    lab.seed_variant_record("rsDUP0002", {"SAMPLE-D": "1|0"})
    policy = lab.create_consent(participant, "cancer_research", "researcher")

    # Two accounts for the same human, but linked to DIFFERENT canonical ids.
    lab.register_identity("dup-acct-3", "canonical-dup-3")
    lab.register_identity("dup-acct-4", "canonical-dup-4")

    def q(requester):
        return lab.query(
            client, participant_id=participant, requester_id=requester,
            project_id="proj-dup2", purpose="cancer_research",
            consent_id=policy.policy_id, variant_id="rsDUP0002",
            sample_id="SAMPLE-D", role="researcher",
        )

    for _ in range(LIMIT):
        assert q("dup-acct-3").status_code == 200
    # The unlinked second account still has its own full budget.
    assert q("dup-acct-4").status_code == 200, (
        "unlinked accounts are not auto-detected; linking must be enforced upstream"
    )
