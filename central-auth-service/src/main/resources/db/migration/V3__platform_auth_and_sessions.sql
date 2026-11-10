-- =============================================================================
-- V3: Platform login challenges, rate limiting, sessions and refresh tokens
-- =============================================================================
-- Rate limiting and lockout state live in PostgreSQL so multiple instances
-- behave consistently (in-memory limiting breaks with multiple instances,
-- Section 20). Platform has its own counters (separate from tenant scope).

-- One-time, short-lived challenges used during onboarding and step-up.
CREATE TABLE platform_login_challenges (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_admin_id  UUID         NOT NULL REFERENCES platform_admins(id) ON DELETE CASCADE,
    challenge_type     VARCHAR(32)  NOT NULL,   -- ONBOARDING|TOTP_STEPUP|PASSWORD_VERIFIED
    token_hash         VARCHAR(255) NOT NULL,   -- hashed challenge token (single-use)
    expires_at         TIMESTAMPTZ  NOT NULL,
    used_at            TIMESTAMPTZ,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX ix_platform_login_challenges_admin
    ON platform_login_challenges (platform_admin_id);
CREATE INDEX ix_platform_login_challenges_token
    ON platform_login_challenges (token_hash);

-- Rate-limit / lockout counters keyed by bucket (e.g. 'platform_login:<ip>',
-- 'totp_verify:<admin_id>'). Replaces (count, window_start) atomically.
CREATE TABLE platform_rate_limit_counters (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    bucket_key    VARCHAR(255) NOT NULL,
    count         BIGINT       NOT NULL DEFAULT 0,
    window_start  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    locked_until  TIMESTAMPTZ,
    UNIQUE (bucket_key)
);

-- Platform sessions. 'sid' is placed in the JWT; 'session_version' captures the
-- 'ver' at issuance so introspection can detect staleness (Section 13, 14).
CREATE TABLE platform_sessions (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_admin_id UUID         NOT NULL REFERENCES platform_admins(id) ON DELETE CASCADE,
    sid               UUID         NOT NULL,    -- session id placed in JWT 'sid' claim
    session_version   BIGINT       NOT NULL,    -- 'ver' at issuance
    ip_address        VARCHAR(64),
    user_agent        VARCHAR(255),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    revoked_at        TIMESTAMPTZ
);
CREATE INDEX ix_platform_sessions_admin  ON platform_sessions (platform_admin_id);
CREATE INDEX ix_platform_sessions_sid     ON platform_sessions (sid);
CREATE INDEX ix_platform_sessions_active  ON platform_sessions (platform_admin_id) WHERE revoked_at IS NULL;

-- Refresh tokens, rotated on every use. Reuse of a rotated token revokes the
-- whole token family and the session (Section 13).
CREATE TABLE platform_refresh_tokens (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_admin_id UUID         NOT NULL REFERENCES platform_admins(id) ON DELETE CASCADE,
    session_id        UUID         NOT NULL REFERENCES platform_sessions(id) ON DELETE CASCADE,
    token_hash        VARCHAR(255) NOT NULL,   -- hashed refresh token
    family_id         UUID         NOT NULL,   -- rotation family; replay revokes family
    generation        INTEGER      NOT NULL DEFAULT 0,
    expires_at        TIMESTAMPTZ  NOT NULL,
    used_at           TIMESTAMPTZ,
    revoked_at        TIMESTAMPTZ,
    revoked_reason    VARCHAR(64),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX ix_platform_refresh_tokens_admin  ON platform_refresh_tokens (platform_admin_id);
CREATE INDEX ix_platform_refresh_tokens_family ON platform_refresh_tokens (family_id);
CREATE INDEX ix_platform_refresh_tokens_active  ON platform_refresh_tokens (family_id) WHERE revoked_at IS NULL;
