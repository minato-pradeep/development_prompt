package com.userrepo.auth.company;

import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/** Per-company auth settings. login_method selects the primary login flow (Section 8). */
@Entity
@Table(name = "company_auth_settings")
public class CompanyAuthSettings {

    @Id
    @Column(name = "company_id", updatable = false, nullable = false)
    private UUID companyId;

    /** PASSWORD_ONLY | PASSWORD_TOTP | MICROSOFT_SSO */
    @Column(name = "login_method", nullable = false)
    private String loginMethod = "PASSWORD_ONLY";

    @Column(name = "min_password_length", nullable = false)
    private int minPasswordLength = 12;

    @Column(name = "password_history_count", nullable = false)
    private int passwordHistoryCount = 5;

    @Column(name = "max_login_failures", nullable = false)
    private int maxLoginFailures = 5;

    @Column(name = "temp_password_ttl_hours", nullable = false)
    private int tempPasswordTtlHours = 72;

    @Column(name = "allowed_client_types")
    private String allowedClientTypes;  // comma-separated

    @Column(name = "mfa_required_for_admin", nullable = false)
    private boolean mfaRequiredForAdmin = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public CompanyAuthSettings() {}

    public UUID getCompanyId() { return companyId; }
    public void setCompanyId(UUID companyId) { this.companyId = companyId; }
    public String getLoginMethod() { return loginMethod; }
    public void setLoginMethod(String loginMethod) { this.loginMethod = loginMethod; }
    public int getMinPasswordLength() { return minPasswordLength; }
    public void setMinPasswordLength(int minPasswordLength) { this.minPasswordLength = minPasswordLength; }
    public int getPasswordHistoryCount() { return passwordHistoryCount; }
    public void setPasswordHistoryCount(int passwordHistoryCount) { this.passwordHistoryCount = passwordHistoryCount; }
    public int getMaxLoginFailures() { return maxLoginFailures; }
    public void setMaxLoginFailures(int maxLoginFailures) { this.maxLoginFailures = maxLoginFailures; }
    public int getTempPasswordTtlHours() { return tempPasswordTtlHours; }
    public void setTempPasswordTtlHours(int tempPasswordTtlHours) { this.tempPasswordTtlHours = tempPasswordTtlHours; }
    public String getAllowedClientTypes() { return allowedClientTypes; }
    public void setAllowedClientTypes(String allowedClientTypes) { this.allowedClientTypes = allowedClientTypes; }
    public boolean isMfaRequiredForAdmin() { return mfaRequiredForAdmin; }
    public void setMfaRequiredForAdmin(boolean mfaRequiredForAdmin) { this.mfaRequiredForAdmin = mfaRequiredForAdmin; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
