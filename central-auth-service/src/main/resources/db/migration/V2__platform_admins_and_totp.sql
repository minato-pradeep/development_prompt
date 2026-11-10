-- =============================================================================
-- V2: Super Admin accounts and platform TOTP
-- =============================================================================
-- Super Admin accounts live in a separate platform-level security scope
-- (platform_admins) and are NOT ordinary company users. Platform queries use a
-- distinct, audited code path. These tables carry no company_id and are not
-- subject to tenant RLS (Section 4).

CREATE TABLE platform_admins (
    id                    UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    username              VARCHAR(64)  NOT NULL,
    email                 VARCHAR(255) NOT NULL,
    password_hash         VARCHAR(255) NOT NULL,                       -- Argon2id encoded hash
    must_change_password  BOOLEAN      NOT NULL DEFAULT FALSE,
    must_enroll_totp      BOOLEAN      NOT NULL DEFAULT FALSE,
    totp_enabled          BOOLEAN      NOT NULL DEFAULT FALSE,
    status                VARCHAR(32)  NOT NULL DEFAULT 'ACTIVE',      -- ACTIVE|LOCKED|DISABLED
    session_version       BIGINT       NOT NULL DEFAULT 0,             -- 'ver' claim source
    failed_login_count    INTEGER      NOT NULL DEFAULT 0,
    locked_until          TIMESTAMPTZ,
    last_login_at         TIMESTAMPTZ,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Super Admin usernames are globally unique (no company scope for the platform).
CREATE UNIQUE INDEX uk_platform_admins_username
    ON platform_admins (lower(username));
CREATE UNIQUE INDEX uk_platform_admins_email
    ON platform_admins (lower(email));
CREATE INDEX ix_platform_admins_status ON platform_admins (status);

-- -----------------------------------------------------------------------------
-- Platform TOTP (RFC 6238). Secrets are encrypted at rest with AES-GCM.
-- -----------------------------------------------------------------------------
CREATE TABLE platform_admin_totp (
    platform_admin_id  UUID         PRIMARY KEY REFERENCES platform_admins(id) ON DELETE CASCADE,
    secret_cipher      BYTEA        NOT NULL,        -- AES-GCM ciphertext (includes appended auth tag)
    secret_iv          BYTEA        NOT NULL,        -- AES-GCM 96-bit nonce
    encryption_kid     VARCHAR(64),                  -- key id used (supports rotation)
    provisioning_uri   TEXT,                         -- otpauth:// URI, cleared after activation
    last_accepted_step BIGINT,                       -- replay prevention (Section 6)
    enrolled_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- -----------------------------------------------------------------------------
-- TOTP recovery codes (single-use, stored hashed). Used for Super Admin MFA
-- recovery (Section 4). Can be regenerated only after strong re-authentication.
-- -----------------------------------------------------------------------------
CREATE TABLE platform_admin_recovery_codes (
    id                 UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    platform_admin_id  UUID         NOT NULL REFERENCES platform_admins(id) ON DELETE CASCADE,
    code_hash          VARCHAR(255) NOT NULL,        -- SHA-256 (or Argon2id) hash of the code
    used_at            TIMESTAMPTZ,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX ix_platform_admin_recovery_codes_admin
    ON platform_admin_recovery_codes (platform_admin_id);
CREATE INDEX ix_platform_admin_recovery_codes_unused
    ON platform_admin_recovery_codes (platform_admin_id) WHERE used_at IS NULL;
