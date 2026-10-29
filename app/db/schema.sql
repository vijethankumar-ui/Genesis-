CREATE TABLE IF NOT EXISTS consent_policies (
    policy_id UUID PRIMARY KEY,
    subject_id VARCHAR(100) NOT NULL,
    data_scope TEXT NOT NULL,
    approved_purpose VARCHAR(255) NOT NULL,
    recipient_role VARCHAR(100) NOT NULL,
    expiry_date TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
        CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ,
    revoked_by VARCHAR(100)
);

CREATE TABLE IF NOT EXISTS governance_audit (
    id BIGSERIAL PRIMARY KEY,
    timestamp TEXT NOT NULL,
    actor_id VARCHAR(100),
    action VARCHAR(100) NOT NULL,
    subject_id VARCHAR(100),
    decision VARCHAR(50) NOT NULL,
    reason TEXT,
    details JSONB,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL
);
