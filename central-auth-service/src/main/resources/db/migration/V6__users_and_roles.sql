-- =============================================================================
-- V6: Users, roles, permissions, mappings, TOTP, sessions, tokens, password
-- =============================================================================

-- Global permission catalog (managed at platform level, Section 11).
-- Companies cannot invent new catalog permissions; microservices register theirs
-- through a controlled endpoint.
CREATE TABLE permissions (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    resource      VARCHAR(64)  NOT NULL,
    action        VARCHAR(64)  NOT NULL,
    description   TEXT,
    registered_by VARCHAR(128),         -- service that registered this permission
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (resource, action)
);

-- Per-company roles. System roles (COMPANY_ADMIN) cannot be deleted (Section 11).
CREATE TABLE roles (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id   UUID         NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    name         VARCHAR(64)  NOT NULL,
    description  TEXT,
    is_system    BOOLEAN      NOT NULL DEFAULT FALSE,   -- true for COMPANY_ADMIN etc.
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    UNIQUE (company_id, name)
);
CREATE INDEX ix_roles_company ON roles (company_id);

-- Role → permission links. Scope: OWN | DEPARTMENT | COMPANY (Section 11).
CREATE TABLE role_permissions (
    role_id       UUID         NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_id UUID         NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    scope         VARCHAR(32)  NOT NULL DEFAULT 'COMPANY',  -- OWN|DEPARTMENT|COMPANY
    PRIMARY KEY (role_id, permission_id)
);

-- Users. A user belongs to exactly one company (Section 3, 10).
CREATE TABLE users (
    id                     UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id             UUID         NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    username               VARCHAR(64)  NOT NULL,
    normalized_username    VARCHAR(64)  NOT NULL,            -- lower-cased; used for unique constraint
    email                  VARCHAR(255),
    mobile_number          VARCHAR(32),
    first_name             VARCHAR(128),
    last_name              VARCHAR(128),
    employee_code          VARCHAR(64),
    department             VARCHAR(128),
    designation            VARCHAR(128),
    status                 VARCHAR(32)  NOT NULL DEFAULT 'PENDING_ACTIVATION',
                                        -- ACTIVE|INACTIVE|LOCKED|PENDING_ACTIVATION|DISABLED
    password_hash          VARCHAR(255),
    must_change_password   BOOLEAN      NOT NULL DEFAULT TRUE,
    must_enroll_totp       BOOLEAN      NOT NULL DEFAULT FALSE,
    totp_enabled           BOOLEAN      NOT NULL DEFAULT FALSE,
    is_company_admin       BOOLEAN      NOT NULL DEFAULT FALSE,
    session_version        BIGINT       NOT NULL DEFAULT 0,
    failed_login_count     INTEGER      NOT NULL DEFAULT 0,
    locked_until           TIMESTAMPTZ,
    last_login_at          TIMESTAMPTZ,
    created_by             UUID,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Username unique within company (composite, normalized). Section 3.
CREATE UNIQUE INDEX uk_users_company_username ON users (company_id, normalized_username);
CREATE INDEX ix_users_company   ON users (company_id);
CREATE INDEX ix_users_status    ON users (company_id, status);
CREATE INDEX ix_users_email     ON users (company_id, email) WHERE email IS NOT NULL;

-- User → role assignments (composite FK ensures cross-tenant assignments are impossible).
CREATE TABLE user_roles (
    user_id    UUID  NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id    UUID  NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

-- User TOTP. Same encrypted-secret pattern as platform (Section 6).
CREATE TABLE user_totp (
    user_id            UUID         PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_cipher      BYTEA        NOT NULL,
    secret_iv          BYTEA        NOT NULL,
    encryption_kid     VARCHAR(64),
    provisioning_uri   TEXT,
    last_accepted_step BIGINT,
    enrolled_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Single-use TOTP recovery codes (hashed), Section 6.
CREATE TABLE totp_recovery_codes (
    id        UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id   UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    used_at   TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_totp_recovery_codes_user ON totp_recovery_codes (user_id);

-- Password history, Section 8.
CREATE TABLE password_history (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX ix_password_history_user ON password_history (user_id);

-- Login challenges for tenant users (onboarding, TOTP, step-up). Section 6.
CREATE TABLE login_challenges (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    company_id      UUID         NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
    challenge_type  VARCHAR(32)  NOT NULL,   -- ONBOARDING|TOTP_VERIFY|STEP_UP|PASSWORD_RESET
    token_hash      VARCHAR(255) NOT NULL,
    client_id       VARCHAR(128),
    device_id       VARCHAR(128),
    expires_at      TIMESTAMPTZ  NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX ix_login_challenges_user  ON login_challenges (user_id);
CREATE INDEX ix_login_challenges_token ON login_challenges (token_hash);

-- Auth clients registry (Section 30.1).
CREATE TABLE auth_clients (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id       VARCHAR(128) NOT NULL UNIQUE,
    display_name    VARCHAR(128) NOT NULL,
    client_type     VARCHAR(32)  NOT NULL,   -- WEB|DESKTOP|MOBILE_IOS|MOBILE_ANDROID|SERVICE
    is_confidential BOOLEAN      NOT NULL DEFAULT FALSE,
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    access_token_ttl_seconds  INTEGER,
    refresh_absolute_ttl_seconds INTEGER,
    refresh_idle_ttl_seconds  INTEGER,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE auth_client_redirect_uris (
    id         UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id  UUID         NOT NULL REFERENCES auth_clients(id) ON DELETE CASCADE,
    uri        VARCHAR(512) NOT NULL,
    UNIQUE (client_id, uri)
);

-- User sessions + refresh tokens with device/client binding (Section 30.5).
CREATE TABLE user_sessions (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    company_id      UUID         NOT NULL REFERENCES companies(id),
    sid             UUID         NOT NULL,
    session_version BIGINT       NOT NULL,
    client_id       VARCHAR(128),
    device_id       VARCHAR(128),
    platform        VARCHAR(32),
    app_version     VARCHAR(32),
    ip_address      VARCHAR(64),
    user_agent      VARCHAR(255),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ
);
CREATE INDEX ix_user_sessions_user     ON user_sessions (user_id);
CREATE INDEX ix_user_sessions_company  ON user_sessions (company_id);
CREATE INDEX ix_user_sessions_sid      ON user_sessions (sid);
CREATE INDEX ix_user_sessions_active   ON user_sessions (user_id) WHERE revoked_at IS NULL;

CREATE TABLE refresh_tokens (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id      UUID         NOT NULL REFERENCES user_sessions(id) ON DELETE CASCADE,
    company_id      UUID         NOT NULL REFERENCES companies(id),
    token_hash      VARCHAR(255) NOT NULL,
    family_id       UUID         NOT NULL,
    generation      INTEGER      NOT NULL DEFAULT 0,
    client_id       VARCHAR(128),
    device_id       VARCHAR(128),
    expires_at      TIMESTAMPTZ  NOT NULL,
    used_at         TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    revoked_reason  VARCHAR(64),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX ix_refresh_tokens_user   ON refresh_tokens (user_id);
CREATE INDEX ix_refresh_tokens_family ON refresh_tokens (family_id);

-- Password reset requests (short-lived, single-use, stored hashed). Section 18.
CREATE TABLE password_reset_requests (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID         NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    company_id      UUID         NOT NULL REFERENCES companies(id),
    token_hash      VARCHAR(255) NOT NULL,
    expires_at      TIMESTAMPTZ  NOT NULL,
    used_at         TIMESTAMPTZ,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX ix_password_reset_user   ON password_reset_requests (user_id);

-- Rate limit counters for tenant login flows (Section 20).
CREATE TABLE rate_limit_counters (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    bucket_key   VARCHAR(255) NOT NULL UNIQUE,
    count        BIGINT       NOT NULL DEFAULT 0,
    window_start TIMESTAMPTZ  NOT NULL DEFAULT now(),
    locked_until TIMESTAMPTZ
);

-- =============================================================================
-- RLS on all tenant user tables
-- =============================================================================

ALTER TABLE users                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles                   ENABLE ROW LEVEL SECURITY;
ALTER TABLE role_permissions        ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles              ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_totp               ENABLE ROW LEVEL SECURITY;
ALTER TABLE totp_recovery_codes     ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_history        ENABLE ROW LEVEL SECURITY;
ALTER TABLE login_challenges        ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions           ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens          ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_requests ENABLE ROW LEVEL SECURITY;

-- Direct company_id columns.
CREATE POLICY users_isolation ON users
    USING (company_id::text = current_setting('app.company_id', true)
           OR current_setting('app.platform_context', true) = 'true');

CREATE POLICY roles_isolation ON roles
    USING (company_id::text = current_setting('app.company_id', true)
           OR current_setting('app.platform_context', true) = 'true');

CREATE POLICY login_challenges_isolation ON login_challenges
    USING (company_id::text = current_setting('app.company_id', true)
           OR current_setting('app.platform_context', true) = 'true');

CREATE POLICY user_sessions_isolation ON user_sessions
    USING (company_id::text = current_setting('app.company_id', true)
           OR current_setting('app.platform_context', true) = 'true');

CREATE POLICY refresh_tokens_isolation ON refresh_tokens
    USING (company_id::text = current_setting('app.company_id', true)
           OR current_setting('app.platform_context', true) = 'true');

CREATE POLICY password_reset_isolation ON password_reset_requests
    USING (company_id::text = current_setting('app.company_id', true)
           OR current_setting('app.platform_context', true) = 'true');

-- Tables with user_id FK (cross-ref via users.company_id).
CREATE POLICY user_totp_isolation ON user_totp
    USING (user_id IN (SELECT id FROM users));

CREATE POLICY totp_recovery_isolation ON totp_recovery_codes
    USING (user_id IN (SELECT id FROM users));

CREATE POLICY password_history_isolation ON password_history
    USING (user_id IN (SELECT id FROM users));

CREATE POLICY user_roles_isolation ON user_roles
    USING (user_id IN (SELECT id FROM users));

-- role_permissions: all roles visible within company.
CREATE POLICY role_permissions_isolation ON role_permissions
    USING (role_id IN (SELECT id FROM roles));
