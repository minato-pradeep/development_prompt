-- =============================================================================
-- V5: Companies, company settings, auth settings, logos
-- =============================================================================
-- Every company has a UUID primary key and a globally unique company_code
-- (human-readable key). Section 3.

CREATE TABLE companies (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    company_code      VARCHAR(32)  NOT NULL,
    name              VARCHAR(255) NOT NULL,
    email             VARCHAR(255),
    contact_number    VARCHAR(32),
    address           TEXT,
    city              VARCHAR(128),
    state             VARCHAR(128),
    country           VARCHAR(64),
    postal_code       VARCHAR(16),
    website           VARCHAR(255),
    tax_registration  VARCHAR(128),
    status            VARCHAR(32)  NOT NULL DEFAULT 'ACTIVE', -- ACTIVE|INACTIVE|SUSPENDED
    time_zone         VARCHAR(64)  NOT NULL DEFAULT 'UTC',
    default_language  VARCHAR(16)  NOT NULL DEFAULT 'en',
    session_version   BIGINT       NOT NULL DEFAULT 0,        -- incremented on status changes
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX uk_companies_code      ON companies (lower(company_code));
CREATE INDEX        ix_companies_status    ON companies (status);

-- Company-level general settings (non-auth). Each company has exactly one row.
CREATE TABLE company_settings (
    company_id             UUID         PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
    date_format            VARCHAR(32)  NOT NULL DEFAULT 'YYYY-MM-DD',
    email_unique_per_company BOOLEAN    NOT NULL DEFAULT TRUE,   -- Section 8
    max_concurrent_sessions INTEGER     NOT NULL DEFAULT 5,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Auth settings: one row per company. login_method is the primary method.
-- Company Admins always retain local password+TOTP regardless (Section 8).
CREATE TABLE company_auth_settings (
    company_id              UUID         PRIMARY KEY REFERENCES companies(id) ON DELETE CASCADE,
    login_method            VARCHAR(32)  NOT NULL DEFAULT 'PASSWORD_ONLY',
                                         -- PASSWORD_ONLY | PASSWORD_TOTP | MICROSOFT_SSO
    min_password_length     INTEGER      NOT NULL DEFAULT 12,
    password_history_count  INTEGER      NOT NULL DEFAULT 5,
    max_login_failures      INTEGER      NOT NULL DEFAULT 5,
    temp_password_ttl_hours INTEGER      NOT NULL DEFAULT 72,
    allowed_client_types    TEXT,        -- comma-separated: WEB,DESKTOP,MOBILE
    mfa_required_for_admin  BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at              TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ  NOT NULL DEFAULT now()
);

-- Company logos. File content stored in configurable private storage (not in DB).
-- Filename, size and MIME metadata stored here. SVG is forbidden; PNG and JPEG only.
-- Section 8.
CREATE TABLE company_logos (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID         NOT NULL UNIQUE REFERENCES companies(id) ON DELETE CASCADE,
    original_name   VARCHAR(255),
    stored_path     VARCHAR(512) NOT NULL,   -- path inside the private storage abstraction
    content_type    VARCHAR(64)  NOT NULL,   -- image/png | image/jpeg (never image/svg+xml)
    size_bytes      BIGINT       NOT NULL,
    width_px        INTEGER,
    height_px       INTEGER,
    uploaded_by     UUID,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX ix_company_logos_company ON company_logos (company_id);

-- =============================================================================
-- Row-Level Security (RLS) for tenant-scoped tables.
-- Migrations run as a privileged role (schema owner) so RLS does not block them.
-- The application role (no BYPASSRLS) sets a per-transaction setting:
--   SET LOCAL app.company_id = '<uuid>';
-- before any tenant-scoped query. The policy below enforces this.
-- Platform-scope tables (platform_admins, audit_logs, signing_keys_metadata) are
-- NOT protected by these policies; they use a distinct code path (Section 3).
-- =============================================================================

ALTER TABLE companies           ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_settings    ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_auth_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_logos       ENABLE ROW LEVEL SECURITY;

-- Super Admin / platform reads bypass the company filter using the SUPERADMIN policy.
-- The application uses a separate DB role for platform operations.
-- The default policy: the app may only see its own company's rows.
-- "current_setting('app.company_id', true)" returns '' when not set (second arg = true).

CREATE POLICY company_isolation ON companies
    USING (
        id::text = current_setting('app.company_id', true)
        OR current_setting('app.platform_context', true) = 'true'
    );

CREATE POLICY company_settings_isolation ON company_settings
    USING (
        company_id::text = current_setting('app.company_id', true)
        OR current_setting('app.platform_context', true) = 'true'
    );

CREATE POLICY company_auth_settings_isolation ON company_auth_settings
    USING (
        company_id::text = current_setting('app.company_id', true)
        OR current_setting('app.platform_context', true) = 'true'
    );

CREATE POLICY company_logos_isolation ON company_logos
    USING (
        company_id::text = current_setting('app.company_id', true)
        OR current_setting('app.platform_context', true) = 'true'
    );
