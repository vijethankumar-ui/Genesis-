
CREATE TABLE IF NOT EXISTS consent_policies (
    policy_id UUID PRIMARY KEY,
    subject_id VARCHAR(100) NOT NULL,
    data_scope TEXT NOT NULL,
    approved_purpose VARCHAR(255) NOT NULL,
    recipient_role VARCHAR(100) NOT NULL,
    expiry_date TIMESTAMPTZ NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

