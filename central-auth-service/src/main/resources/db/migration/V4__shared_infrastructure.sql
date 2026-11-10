-- =============================================================================
-- V4: Shared infrastructure - audit logs and signing key metadata
-- =============================================================================
-- Append-only audit log. company_id is NULL for platform-level events and
-- non-NULL for tenant events. Enforced append-only for the application role
-- at provisioning time (INSERT only); see docs/db-provisioning.sql.
-- Record fields per Section 19.
CREATE TABLE audit_logs (
    id             UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type     VARCHAR(64)  NOT NULL,
    actor_type     VARCHAR(32),                 -- PLATFORM_ADMIN|USER|SERVICE_CLIENT|SYSTEM
    actor_id       UUID,
    company_id     UUID,                        -- NULL for platform-level events
    target_type    VARCHAR(32),
    target_id      UUID,
    result         VARCHAR(32)  NOT NULL,       -- SUCCESS|FAILURE
    correlation_id VARCHAR(64),
    ip_address     VARCHAR(64),
    metadata       TEXT,                        -- JSON string of event details (TEXT avoids Hibernate/JSON binding risk; see MANUAL_CHANGES_NEEDED.md for an optional JSONB upgrade)
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_logs_created     ON audit_logs (created_at);
CREATE INDEX ix_audit_logs_company      ON audit_logs (company_id);
CREATE INDEX ix_audit_logs_event_type   ON audit_logs (event_type);
CREATE INDEX ix_audit_logs_actor        ON audit_logs (actor_id);

-- Metadata for JWT signing keys (Section 13). The private key lives in a
-- keystore / Vault / cloud KMS, never in the repository. JWTs carry a 'kid'
-- matching this table's primary key. Rotation uses an overlap window during
-- which the old public key stays available via JWKS.
CREATE TABLE signing_keys_metadata (
    kid            VARCHAR(64)  PRIMARY KEY,
    algorithm      VARCHAR(16)  NOT NULL,        -- ES256
    public_jwk     TEXT         NOT NULL,        -- public key as a JWK (JSON), for JWKS / verification
    status         VARCHAR(16)  NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE|RETIRED|REVOKED
    not_before     TIMESTAMPTZ  NOT NULL,
    not_after      TIMESTAMPTZ,                  -- rotation overlap window end
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    retired_at     TIMESTAMPTZ
);
CREATE INDEX ix_signing_keys_status ON signing_keys_metadata (status);
