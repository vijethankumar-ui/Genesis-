"""Attack 2 - Consent revocation bypass.

A participant grants consent, a researcher gets authorized access, then the
participant revokes consent. The researcher tries another query, and also tries
reusing a token that was issued *before* revocation.

Expected secure behaviour:
  - access works while consent is ACTIVE,
  - after revocation, new queries are rejected (403),
  - a pre-revocation token cannot bypass revocation (consent is re-checked each
    query; the token carries no standing authorization),
  - the revocation is recorded in the audit log.

This proves revocation actually prevents access, not merely flips a DB flag.
"""

from security_testing import lab


def test_revoked_consent_blocks_access(client):
    participant = "participant-REV"
    requester = "researcher-rev"
    role = "researcher"
    variant = "rsREVOKE01"
    sample = "SAMPLE-R"

    lab.register_identity(requester, "canonical-rev")
    lab.seed_variant_record(variant, {sample: "1|0"})
    policy = lab.create_consent(participant, "cancer_research", role)

    # A token minted before revocation (the attacker's "captured" credential).
    pre_revocation_token = lab.make_auth_token(requester, role)

    def run_query():
        return lab.query(
            client,
            participant_id=participant,
            requester_id=requester,
            project_id="proj-rev",
            purpose="cancer_research",
            consent_id=policy.policy_id,
            variant_id=variant,
            sample_id=sample,
            role=role,
            token=pre_revocation_token,
        )

    # 1. Authorized access works while consent is ACTIVE.
    assert run_query().status_code == 200

    # 2. Revoke consent.
    revoked = lab.revoke_consent(policy.policy_id)
    assert revoked is not None and revoked.status == "REVOKED"

    # 3. A fresh query is now rejected.
    fresh = lab.query(
        client,
        participant_id=participant,
        requester_id=requester,
        project_id="proj-rev",
        purpose="cancer_research",
        consent_id=policy.policy_id,
        variant_id=variant,
        sample_id=sample,
        role=role,
    )
    assert fresh.status_code == 403, fresh.text

    # 4. The pre-revocation token cannot bypass revocation either.
    assert run_query().status_code == 403

    # 5. The revocation is auditable.
    actions = [row[0] for row in lab.latest_audit_events(limit=20)]
    assert "CONSENT_REVOKED" in actions
