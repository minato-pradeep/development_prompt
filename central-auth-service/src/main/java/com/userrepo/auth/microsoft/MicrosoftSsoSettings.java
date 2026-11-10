package com.userrepo.auth.microsoft;

import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/** Microsoft Entra ID SSO configuration per company (Section 9). */
@Entity
@Table(name = "microsoft_sso_settings")
public class MicrosoftSsoSettings {

    @Id
    @Column(name = "company_id", updatable = false, nullable = false)
    private UUID companyId;

    @Column(name = "tenant_id", nullable = false)
    private String tenantId;

    @Column(name = "client_id_value", nullable = false)
    private String clientIdValue;

    /** Reference to a secret manager entry — NOT the actual secret. */
    @Column(name = "client_secret_ref")
    private String clientSecretRef;

    @Column(name = "redirect_uri", nullable = false)
    private String redirectUri;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = false;

    @Column(name = "provisioning_policy", nullable = false)
    private String provisioningPolicy = "MANUAL";

    @Column(name = "jit_default_role_id")
    private UUID jitDefaultRoleId;

    @Column(name = "jit_requires_approval", nullable = false)
    private boolean jitRequiresApproval = true;

    /** Required AMR value in Entra token (e.g. "mfa"). */
    @Column(name = "required_amr")
    private String requiredAmr;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public MicrosoftSsoSettings() {}

    public UUID getCompanyId() { return companyId; }
    public void setCompanyId(UUID c) { this.companyId = c; }
    public String getTenantId() { return tenantId; }
    public void setTenantId(String t) { this.tenantId = t; }
    public String getClientIdValue() { return clientIdValue; }
    public void setClientIdValue(String c) { this.clientIdValue = c; }
    public String getClientSecretRef() { return clientSecretRef; }
    public void setClientSecretRef(String c) { this.clientSecretRef = c; }
    public String getRedirectUri() { return redirectUri; }
    public void setRedirectUri(String r) { this.redirectUri = r; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean e) { this.enabled = e; }
    public String getProvisioningPolicy() { return provisioningPolicy; }
    public void setProvisioningPolicy(String p) { this.provisioningPolicy = p; }
    public UUID getJitDefaultRoleId() { return jitDefaultRoleId; }
    public void setJitDefaultRoleId(UUID j) { this.jitDefaultRoleId = j; }
    public boolean isJitRequiresApproval() { return jitRequiresApproval; }
    public void setJitRequiresApproval(boolean j) { this.jitRequiresApproval = j; }
    public String getRequiredAmr() { return requiredAmr; }
    public void setRequiredAmr(String r) { this.requiredAmr = r; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant c) { this.createdAt = c; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant u) { this.updatedAt = u; }
}
