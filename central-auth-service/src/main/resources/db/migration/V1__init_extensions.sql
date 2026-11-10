-- =============================================================================
-- V1: Extensions and baseline
-- =============================================================================
-- pgcrypto provides gen_random_uuid(), used as the DEFAULT for all UUID
-- primary keys. UUIDs are used for every internal identifier (Section 3, 17).
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Row-Level Security roles:
--   * The application connects as a NON-OWNER role WITHOUT BYPASSRLS, so RLS
--     policies apply to it. Provisioning of that role is a deployment step
--     (see docs/db-provisioning.sql and MANUAL_CHANGES_NEEDED.md), NOT done in
--     Flyway, so that no secrets are committed and roles can be managed
--     externally (Section 3, 20).
--   * Migrations run as a separate privileged role (schema owner) which is
--     exempt from RLS by default.
-- Phase 1 creates only platform-scope tables (no company_id, no RLS).
-- Tenant-scoped tables + RLS policies are added in Phase 2.
