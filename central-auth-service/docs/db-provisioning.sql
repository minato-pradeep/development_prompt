-- =============================================================================
-- DB Provisioning Script (run once by the schema owner / DBA)
-- Creates the application role with no BYPASSRLS and grants only what it needs.
-- Migrations run as the schema owner (BYPASSRLS by default for owners).
-- =============================================================================

-- Application role (no BYPASSRLS): used at runtime.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'central_auth_app') THEN
        CREATE ROLE central_auth_app WITH LOGIN PASSWORD 'dev_app_pass' NOINHERIT;
    END IF;
END
$$;

-- Grant usage on schema and tables.
GRANT USAGE ON SCHEMA public TO central_auth_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO central_auth_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO central_auth_app;

-- Future tables.
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE ON TABLES TO central_auth_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT USAGE ON SEQUENCES TO central_auth_app;

-- The application role must NOT have BYPASSRLS.
-- Row-Level Security is enforced by per-transaction SET LOCAL app.company_id.
-- Verify: SELECT rolbypassrls FROM pg_roles WHERE rolname = 'central_auth_app';
-- Expected: f (false)
