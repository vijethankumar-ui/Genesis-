CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS consent_policies (
    policy_id UUID PRIMARY KEY,
    subject_id VARCHAR(200) NOT NULL,
    data_scope VARCHAR(200) NOT NULL,
    approved_purpose VARCHAR(300) NOT NULL,
    recipient_role VARCHAR(100) NOT NULL,
    expiry_date DATE NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'REVOKED'))
);

CREATE TABLE IF NOT EXISTS audit_logs (
    sequence_id BIGINT PRIMARY KEY,
    event_id UUID NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    event_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor VARCHAR(200) NOT NULL,
    subject_id VARCHAR(200),
    data_scope VARCHAR(200),
    purpose VARCHAR(300),
    policy_id UUID,
    decision VARCHAR(30) NOT NULL,
    reason TEXT NOT NULL,
    previous_hash VARCHAR(64) NOT NULL,
    event_hash VARCHAR(64) NOT NULL
);

CREATE OR REPLACE FUNCTION prevent_audit_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_logs_no_update ON audit_logs;
CREATE TRIGGER audit_logs_no_update BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_mutation();
