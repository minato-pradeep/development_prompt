package com.userrepo.auth.security;

import jakarta.persistence.EntityManager;
import org.springframework.stereotype.Component;

import java.util.UUID;

/**
 * Sets per-transaction PostgreSQL session settings that activate Row-Level Security
 * policies (Section 3, 20).
 *
 * <p>Must be called inside an active transaction (before any tenant-scoped query).
 * Platform operations set {@code app.platform_context = 'true'} instead of a
 * company_id so the platform bypass policies apply.
 *
 * <p>The application role does NOT have BYPASSRLS; the RLS policies in V5-V7 enforce
 * isolation even if the application layer is bypassed.
 */
@Component
public class TenantContext {

    private final EntityManager entityManager;

    public TenantContext(EntityManager entityManager) {
        this.entityManager = entityManager;
    }

    /** Activate tenant isolation for the current transaction. */
    public void setCompany(UUID companyId) {
        entityManager.createNativeQuery(
                "SET LOCAL app.company_id = '" + companyId + "'").executeUpdate();
        entityManager.createNativeQuery(
                "SET LOCAL app.platform_context = 'false'").executeUpdate();
    }

    /** Activate platform context (Super Admin) — bypasses tenant RLS policies. */
    public void setPlatform() {
        entityManager.createNativeQuery(
                "SET LOCAL app.platform_context = 'true'").executeUpdate();
        entityManager.createNativeQuery(
                "SET LOCAL app.company_id = ''").executeUpdate();
    }
}
