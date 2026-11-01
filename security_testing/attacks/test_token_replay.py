"""Attack 7 - Token replay and expiration.

An attacker captures or crafts authorization tokens and tries to reuse them
outside their permitted scope.

Verified here:
  - expired token               -> 401 (rejected),
  - wrong token type (scoped)   -> 401 (only authentication tokens accepted),
  - bad signature               -> 401,
  - token used after revocation -> 403 (consent re-checked each query),
  - FINDING: a still-valid token is replayable (no jti/nonce / not single-use);
    the same captured token answers multiple queries within its lifetime.
"""

import jwt

from security_testing import lab


def _args(participant, requester, policy):
    return dict(
        participant_id=participant, requester_id=requester,
        project_id="proj-tok", purpose="cancer_research",
        consent_id=policy.policy_id, variant_id="rsTOK0001",
        sample_id="SAMPLE-T", role="researcher",
    )


def _prepare(client, participant, requester):
    lab.register_identity(requester, f"canonical-{requester}")
    lab.seed_variant_record("rsTOK0001", {"SAMPLE-T": "1|0"})
    return lab.create_consent(participant, "cancer_research", "researcher")


def test_expired_token_is_rejected(client):
    participant, requester = "participant-TOK1", "tok-user-1"
    policy = _prepare(client, participant, requester)
    expired = lab.make_auth_token(requester, "researcher", minutes=-5)
    resp = lab.query(client, token=expired, **_args(participant, requester, policy))
    assert resp.status_code == 401, resp.text


def test_wrong_token_type_is_rejected(client):
    participant, requester = "participant-TOK2", "tok-user-2"
    policy = _prepare(client, participant, requester)
    scoped = lab.make_auth_token(requester, "researcher", token_type="scoped_access")
    resp = lab.query(client, token=scoped, **_args(participant, requester, policy))
    assert resp.status_code == 401, resp.text


def test_bad_signature_token_is_rejected(client):
    participant, requester = "participant-TOK3", "tok-user-3"
    policy = _prepare(client, participant, requester)
    forged = jwt.encode(
        {"sub": requester, "role": "researcher", "type": "authentication"},
        "not-the-real-secret",
        algorithm="HS256",
    )
    resp = lab.query(client, token=forged, **_args(participant, requester, policy))
    assert resp.status_code == 401, resp.text


def test_token_after_revocation_is_rejected(client):
    participant, requester = "participant-TOK4", "tok-user-4"
    policy = _prepare(client, participant, requester)
    token = lab.make_auth_token(requester, "researcher")

    assert lab.query(client, token=token, **_args(participant, requester, policy)).status_code == 200
    lab.revoke_consent(policy.policy_id)
    # Same captured token, but consent is gone.
    assert lab.query(client, token=token, **_args(participant, requester, policy)).status_code == 403


def test_valid_token_is_replayable_FINDING(client):
    """FINDING: tokens are not single-use; a captured valid token replays."""
    participant, requester = "participant-TOK5", "tok-user-5"
    policy = _prepare(client, participant, requester)
    token = lab.make_auth_token(requester, "researcher")

    first = lab.query(client, token=token, **_args(participant, requester, policy))
    second = lab.query(client, token=token, **_args(participant, requester, policy))

    assert first.status_code == 200
    assert second.status_code == 200, "same token replays (no nonce/jti, not single-use)"
