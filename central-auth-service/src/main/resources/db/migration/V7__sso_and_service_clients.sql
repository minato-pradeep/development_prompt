-- =============================================================================
-- V7: Microsoft SSO settings, external identity mappings, service clients
-- =============================================================================

-- Microsoft Entra ID SSO configuration per company (Section 9).
CREATE TABLE microsoft_sso_settings (
    company_id            UUID         PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
    tenant_id             VARCHAR(128) NOT NULL,   -- Entra tenant ID (tid)
    client_id_value       VARCHAR(255) NOT NULL,   -- Azure app registration client ID
    client_secret_ref     VARCHAR(512),            -- reference to secret manager key, not the secret
    redirect_uri          VARCHAR(512) NOT NULL,
    enabled               BOOLEAN      NOT NULL DEFAULT FALSE,
    provisioning_policy   VARCHAR(32)  NOT NULL DEFAULT 'MANUAL',  -- MANUAL|JIT_PROVISIONING
    jit_default_role_id   UUID,
    jit_requires_approval BOOLEAN      NOT NULL DEFAULT TRUE,
    required_amr          VARCHAR(64),             -- e.g. 'mfa' — required claim in Entra token
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Explicit user → Microsoft identity mapping. No auto-link by email. Section 9.
CREATE TABLE user_external_identities (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    company_id    UUID         NOT NULL REFERENCES companies(id),
    provider      VARCHAR(32)  NOT NULL DEFAULT 'MICROSOFT',
    tid           VARCHAR(128) NOT NULL,   -- Entra tenant ID
    oid           VARCHAR(128) NOT NULL,   -- Entra object ID
    email         VARCHAR(255),
    display_name  VARCHAR(255),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    -- (provider, tid, oid) is globally unique (Section 9).
    UNIQUE (provider, tid, oid)
);
CREATE INDEX ix_user_ext_id_user    ON user_external_identities (user_id);
CREATE INDEX ix_user_ext_id_company ON user_external_identities (company_id);

-- Microsoft OAuth2 state/nonce store for PKCE flow (short-lived). Section 9.
CREATE TABLE microsoft_sso_states (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id   UUID         NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    state        VARCHAR(255) NOT NULL UNIQUE,
    nonce        VARCHAR(255) NOT NULL,
    code_verifier VARCHAR(255) NOT NULL,  -- PKCE S256 verifier
    client_id    VARCHAR(128),
    expires_at   TIMESTAMPTZ  NOT NULL,
    used_at      TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX ix_microsoft_sso_states_state ON microsoft_sso_states (state);

-- Internal single-use authorization codes (Section 9 token-exchange flow).
CREATE TABLE internal_auth_codes (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    code_hash       VARCHAR(255) NOT NULL UNIQUE,
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    company_id      UUID         NOT NULL REFERENCES companies(id),
    client_id       VARCHAR(128),
    pkce_challenge  VARCHAR(255),  -- S256 code_challenge bound to this code
    expires_at      TIMESTAMPTZ   NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT now()
);

-- Service clients for machine-to-machine OAuth 2.0 client credentials (Section 14).
CREATE TABLE service_clients (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       VARCHAR(128) NOT NULL UNIQUE,
    display_name    VARCHAR(128) NOT NULL,
    secret_hash     VARCHAR(255),              -- hashed client secret (or null for private-key JWT)
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE service_client_scopes (
    client_id  UUID         NOT NULL REFERENCES service_clients(id) ON DELETE CASCADE,
    scope      VARCHAR(128) NOT NULL,
    PRIMARY KEY (client_id, scope)
);

-- =============================================================================
-- RLS on tenant-scoped SSO / identity tables
-- =============================================================================

ALTER TABLE microsoft_sso_settings    ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_external_identities  ENABLE ROW LEVEL SECURITY;
ALTER TABLE microsoft_sso_states      ENABLE ROW LEVEL SECURITY;
ALTER TABLE internal_auth_codes       ENABLE ROW LEVEL SECURITY;

CREATE POLICY sso_settings_isolation ON microsoft_sso_settings
    USING (company_id::text = current_setting('app.company_id', true)
           OR current_setting('app.platform_context', true) = 'true');

CREATE POLICY ext_identity_isolation ON user_external_identities
    USING (company_id::text = current_setting('app.company_id', true)
           OR current_setting('app.platform_context', true) = 'true');

CREATE POLICY sso_state_isolation ON microsoft_sso_states
    USING (company_id::text = current_setting('app.company_id', true)
           OR current_setting('app.platform_context', true) = 'true');

CREATE POLICY internal_auth_code_isolation ON internal_auth_codes
    USING (company_id::text = current_setting('app.company_id', true)
           OR current_setting('app.platform_context', true) = 'true');
