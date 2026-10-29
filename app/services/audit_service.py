import hashlib
import json
from app.db.database import get_connection

def append_audit_event(actor: str, subject_id: str | None, data_scope: str | None,
                       purpose: str | None, policy_id: str | None,
                       decision: str, reason: str) -> None:
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT event_hash FROM audit_logs ORDER BY sequence_id DESC LIMIT 1")
            previous = cur.fetchone()
            previous_hash = previous[0] if previous else "GENESIS"
            cur.execute("""
                SELECT COALESCE(MAX(sequence_id), 0) + 1 FROM audit_logs
            """)
            sequence_id = cur.fetchone()[0]
            payload = {
                "sequence_id": sequence_id, "actor": actor, "subject_id": subject_id,
                "data_scope": data_scope, "purpose": purpose, "policy_id": policy_id,
                "decision": decision, "reason": reason, "previous_hash": previous_hash,
            }
            event_hash = hashlib.sha256(
                (previous_hash + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode()
            ).hexdigest()
            cur.execute("""
                INSERT INTO audit_logs
                (sequence_id, actor, subject_id, data_scope, purpose, policy_id,
                 decision, reason, previous_hash, event_hash)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (sequence_id, actor, subject_id, data_scope, purpose, policy_id,
                  decision, reason, previous_hash, event_hash))

def verify_audit_chain() -> bool:
    import hashlib, json
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT sequence_id, actor, subject_id, data_scope, purpose, policy_id,
                       decision, reason, previous_hash, event_hash
                FROM audit_logs ORDER BY sequence_id
            """)
            rows = cur.fetchall()
    previous_hash = "GENESIS"
    for row in rows:
        sequence_id, actor, subject_id, data_scope, purpose, policy_id, decision, reason, stored_previous, stored_hash = row
        if stored_previous != previous_hash:
            return False
        payload = {
            "sequence_id": sequence_id, "actor": actor, "subject_id": subject_id,
            "data_scope": data_scope, "purpose": purpose, "policy_id": policy_id,
            "decision": decision, "reason": reason, "previous_hash": stored_previous,
        }
        expected = hashlib.sha256(
            (stored_previous + json.dumps(payload, sort_keys=True, separators=(",", ":"))).encode()
        ).hexdigest()
        if expected != stored_hash:
            return False
        previous_hash = stored_hash
    return True
