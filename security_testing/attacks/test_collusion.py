"""Attack 5 - Collusion.

Two *distinct* researchers (different canonical identities), both legitimately
authorized for the same participant, split their queries to extract more than a
shared policy should allow.

FINDING: the disclosure budget is keyed per (canonical) requester. There is no
project-level or participant-level shared cap across distinct researchers, so
each gets an independent allowance of 10. By colluding, A and B jointly obtain
20 disclosures about the same participant - double the per-researcher limit.
Member 3 confirmed project-level validation is not implemented.
"""

from security_testing import lab

LIMIT = 10


def test_collusion_bypasses_per_researcher_limit_FINDING(client):
    participant = "participant-COLLUDE"
    lab.seed_variant_record("rsCOL0001", {"SAMPLE-C": "1|0"})
    # One consent policy for the researcher role; both colluders share the role.
    policy = lab.create_consent(participant, "cancer_research", "researcher")

    lab.register_identity("colluder-A", "canonical-A")
    lab.register_identity("colluder-B", "canonical-B")

    def q(requester):
        return lab.query(
            client, participant_id=participant, requester_id=requester,
            project_id="proj-shared", purpose="cancer_research",
            consent_id=policy.policy_id, variant_id="rsCOL0001",
            sample_id="SAMPLE-C", role="researcher",
        )

    a_ok = sum(q("colluder-A").status_code == 200 for _ in range(LIMIT))
    b_ok = sum(q("colluder-B").status_code == 200 for _ in range(LIMIT))

    assert a_ok == LIMIT
    assert b_ok == LIMIT

    # Combined disclosures about ONE participant on ONE project exceed the limit.
    combined = a_ok + b_ok
    assert combined == 2 * LIMIT, (
        f"collusion yielded {combined} disclosures; no shared project-level cap exists"
    )
