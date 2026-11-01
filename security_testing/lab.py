"""Reusable attack-lab helpers.

These wrap the integrated GENESIS backend so attack scripts stay short and
readable. Everything here talks to the SAME cached service instances the live
``/query`` pipeline uses (via ``app.main``), so budget / identity / vault state
observed in a test is exactly the state the API enforced.

Because this is a *local* lab and we control ``JWT_SECRET_KEY``, we mint our own
JWTs to impersonate arbitrary researchers and admins. That is the legitimate way
to simulate multiple identities; it is not an attack on the token signature.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt

GENOMIC_SCOPE = "genomic_variant_data"


# --------------------------------------------------------------------------- #
# Authentication: forge valid JWTs for arbitrary identities / roles.
# --------------------------------------------------------------------------- #
def _secret() -> str:
    from app.core.config import JWT_SECRET_KEY

    if not JWT_SECRET_KEY:
        raise RuntimeError("JWT_SECRET_KEY is not configured in .env")
    return JWT_SECRET_KEY


def make_auth_token(
    sub: str,
    role: str,
    minutes: float = 10,
    token_type: str = "authentication",
) -> str:
    """Mint an authentication JWT. ``minutes`` may be negative for an expired token."""
    now = datetime.now(timezone.utc)
    claims = {
        "sub": sub,
        "username": sub,
        "role": role,
        "type": token_type,
        "token_type": "access",
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }
    return jwt.encode(claims, _secret(), algorithm="HS256")


def auth_header(sub: str, role: str, **kwargs) -> dict[str, str]:
    """Return an Authorization header for the given identity."""
    return {"Authorization": f"Bearer {make_auth_token(sub, role, **kwargs)}"}


# --------------------------------------------------------------------------- #
# Identity registry (canonical-identity linking used by the budget).
# --------------------------------------------------------------------------- #
def register_identity(requester_id: str, canonical_identity_id: str) -> None:
    """Link an account to a canonical identity. Idempotent for re-runs."""
    from app.main import get_identity_registry

    try:
        get_identity_registry().register(requester_id, canonical_identity_id)
    except ValueError:
        # Already registered (links are never overwritten by design).
        pass


# --------------------------------------------------------------------------- #
# Vault seeding (synthetic genomic records).
# --------------------------------------------------------------------------- #
def seed_variant_record(variant_id: str, genotypes: dict[str, str]) -> str:
    """Store a synthetic variant record in the encrypted vault and index it.

    ``genotypes`` maps sample_id -> VCF genotype string, e.g. {"SAMPLE-A": "1|0"}.
    Returns the vault record_id.
    """
    from app.main import get_vault_repository

    record = {"variant_id": variant_id, "genotypes": genotypes}
    return get_vault_repository().store_record(record)


# --------------------------------------------------------------------------- #
# Consent policies (PostgreSQL, via the real service layer).
# --------------------------------------------------------------------------- #
def create_consent(
    subject_id: str,
    approved_purpose: str,
    recipient_role: str,
    data_scope: str = GENOMIC_SCOPE,
    valid_days: int = 30,
):
    """Create an ACTIVE consent policy and return the ConsentPolicy (has .policy_id)."""
    from app.models.consent import ConsentPolicyCreate
    from app.services.consent_service import create_consent_policy

    data = ConsentPolicyCreate(
        subject_id=subject_id,
        data_scope=data_scope,
        approved_purpose=approved_purpose,
        recipient_role=recipient_role,
        expiry_date=datetime.now(timezone.utc) + timedelta(days=valid_days),
    )
    return create_consent_policy(data)


def revoke_consent(policy_id: UUID | str, actor_id: str = "admin"):
    """Revoke a consent policy directly through the service layer."""
    from app.services.consent_service import revoke_consent_policy

    return revoke_consent_policy(UUID(str(policy_id)), actor_id=actor_id)


# --------------------------------------------------------------------------- #
# Disclosure budget inspection.
# --------------------------------------------------------------------------- #
def budget_status(
    participant_id: str,
    requester_id: str,
    project_id: str,
    purpose: str,
    consent_id: str,
) -> dict:
    """Return {'limit','used','remaining'} for one budget scope (requester resolved)."""
    from app.main import get_budget

    return get_budget().get_status(
        participant_id, requester_id, project_id, purpose, consent_id
    )


# --------------------------------------------------------------------------- #
# Governance audit inspection.
# --------------------------------------------------------------------------- #
def latest_audit_events(limit: int = 10) -> list[tuple]:
    """Return the most recent audit rows: (action, subject_id, decision, reason)."""
    from app.db.database import get_connection

    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT action, subject_id, decision, reason
                FROM governance_audit
                ORDER BY id DESC
                LIMIT %s
                """,
                (limit,),
            )
            return cur.fetchall()


def query(client, *, participant_id, requester_id, project_id, purpose,
          consent_id, variant_id, query_type="variant_presence",
          sample_id=None, cost=1, role="researcher", token=None):
    """Convenience wrapper: POST /query as ``requester_id`` with a forged token.

    Pass ``token`` to override the Authorization header (e.g. an expired or
    mismatched token) for replay / token tests.
    """
    headers = {"Authorization": f"Bearer {token}"} if token else auth_header(requester_id, role)
    body = {
        "participant_id": participant_id,
        "requester_id": requester_id,
        "project_id": project_id,
        "purpose": purpose,
        "consent_id": str(consent_id),
        "query_type": query_type,
        "variant_id": variant_id,
        "cost": cost,
    }
    if sample_id is not None:
        body["sample_id"] = sample_id
    return client.post("/query", json=body, headers=headers)
