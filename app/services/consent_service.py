
from uuid import UUID, uuid4

import psycopg

from app.core.config import (
    DB_HOST,
    DB_PORT,
    DB_NAME,
    DB_USER,
    DB_PASSWORD,
)
from app.models.consent import ConsentPolicy, ConsentPolicyCreate
from app.services.audit_service import append_audit_event

def create_consent_policy(data: ConsentPolicyCreate) -> ConsentPolicy:
    policy_id = uuid4()

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
                INSERT INTO consent_policies (
                    policy_id,
                    subject_id,
                    data_scope,
                    approved_purpose,
                    recipient_role,
                    expiry_date,
                    status
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING policy_id, subject_id, data_scope,
                          approved_purpose, recipient_role,
                          expiry_date, status
                """,
                (
                    policy_id,
                    data.subject_id,
                    data.data_scope,
                    data.approved_purpose,
                    data.recipient_role,
                    data.expiry_date,
                    "ACTIVE",
                ),
            )
            row = cursor.fetchone()

    return ConsentPolicy(
        policy_id=row[0],
        subject_id=row[1],
        data_scope=row[2],
        approved_purpose=row[3],
        recipient_role=row[4],
        expiry_date=row[5],
        status=row[6],
    )


def get_consent_policy(policy_id: UUID) -> ConsentPolicy | None:
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
                SELECT policy_id, subject_id, data_scope,
                       approved_purpose, recipient_role,
                       expiry_date, status
                FROM consent_policies
                WHERE policy_id = %s
                """,
                (policy_id,),
            )
            row = cursor.fetchone()

    if row is None:
        return None

    return ConsentPolicy(
        policy_id=row[0],
        subject_id=row[1],
        data_scope=row[2],
        approved_purpose=row[3],
        recipient_role=row[4],
        expiry_date=row[5],
        status=row[6],
    )


def revoke_consent_policy(
    policy_id: UUID,
    actor_id: str | None = None,
) -> ConsentPolicy | None:
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
                UPDATE consent_policies
                SET status = 'REVOKED',
                    revoked_at = CURRENT_TIMESTAMP,
                    revoked_by = %s
                WHERE policy_id = %s
                  AND status = 'ACTIVE'
                RETURNING policy_id, subject_id, data_scope,
                          approved_purpose, recipient_role,
                          expiry_date, status
                """,
                (actor_id, policy_id),
            )
            row = cursor.fetchone()

    if row is None:
        return None

    append_audit_event(
        actor=actor_id,
        subject_id=row[1],
        data_scope=row[2],
        purpose=row[3],
        policy_id=str(row[0]),
        decision="SUCCESS",
        reason="Consent policy revoked.",
        action="CONSENT_REVOKED",
    )

    return ConsentPolicy(
        policy_id=row[0],
        subject_id=row[1],
        data_scope=row[2],
        approved_purpose=row[3],
        recipient_role=row[4],
        expiry_date=row[5],
        status=row[6],
    )
