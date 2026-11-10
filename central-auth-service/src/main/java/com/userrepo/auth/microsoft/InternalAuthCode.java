package com.userrepo.auth.microsoft;

import jakarta.persistence.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

/** Single-use internal authorization code for the token-exchange flow (Section 9). */
@Entity
@Table(name = "internal_auth_codes")
public class InternalAuthCode {

    @Id
    @UuidGenerator
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "code_hash", nullable = false, unique = true)
    private String codeHash;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "company_id", nullable = false)
    private UUID companyId;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "pkce_challenge")
    private String pkceChallenge;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public InternalAuthCode() {}

    public UUID getId() { return id; }
    public void setId(UUID i) { this.id = i; }
    public String getCodeHash() { return codeHash; }
    public void setCodeHash(String c) { this.codeHash = c; }
    public UUID getUserId() { return userId; }
    public void setUserId(UUID u) { this.userId = u; }
    public UUID getCompanyId() { return companyId; }
    public void setCompanyId(UUID c) { this.companyId = c; }
    public String getClientId() { return clientId; }
    public void setClientId(String c) { this.clientId = c; }
    public String getPkceChallenge() { return pkceChallenge; }
    public void setPkceChallenge(String p) { this.pkceChallenge = p; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant e) { this.expiresAt = e; }
    public Instant getUsedAt() { return usedAt; }
    public void setUsedAt(Instant u) { this.usedAt = u; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant c) { this.createdAt = c; }
}
