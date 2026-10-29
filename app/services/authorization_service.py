import psycopg

from app.core.config import (
    DB_HOST,
    DB_PORT,
    DB_NAME,
    DB_USER,
    DB_PASSWORD,
)
from app.models.authorization import AccessRequest, AuthorizationDecision
from app.services.audit_service import append_audit_event


def authorize_access(
    request: AccessRequest,
    actor_id: str | None = None,
) -> AuthorizationDecision:
    if not DB_PASSWORD:
        raise RuntimeError("DB_PASSWORD is missing from .env")

    with psycopg.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    ) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT policy_id
                FROM consent_policies
                WHERE subject_id = %s
                  AND data_scope = %s
                  AND approved_purpose = %s
                  AND recipient_role = %s
                  AND status = 'ACTIVE'
                  AND expiry_date >= CURRENT_DATE
                ORDER BY expiry_date DESC, policy_id
                LIMIT 1
                """,
                (
                    request.subject_id,
                    request.data_scope,
                    request.purpose,
                    request.recipient_role,
                ),
            )
            row = cursor.fetchone()

    if row is None:
        decision = AuthorizationDecision(
            decision="DENY",
            reason=(
                "No active, unexpired consent policy matches "
                "all requested conditions."
            ),
        )

        append_audit_event(
            actor=actor_id,
            subject_id=request.subject_id,
            data_scope=request.data_scope,
            purpose=request.purpose,
            policy_id=None,
            decision=decision.decision,
            reason=decision.reason,
        )

        return decision

    decision = AuthorizationDecision(
        decision="PERMIT",
        reason="A matching active, unexpired consent policy was found.",
        policy_id=str(row[0]),
    )

    append_audit_event(
        actor=actor_id,
        subject_id=request.subject_id,
        data_scope=request.data_scope,
        purpose=request.purpose,
        policy_id=decision.policy_id,
        decision=decision.decision,
        reason=decision.reason,
    )

    return decision