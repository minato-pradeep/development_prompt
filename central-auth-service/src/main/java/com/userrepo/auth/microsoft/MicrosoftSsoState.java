package com.userrepo.auth.microsoft;

import jakarta.persistence.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

/** OAuth2 state/nonce/PKCE store for the Microsoft Entra authorization flow (Section 9). */
@Entity
@Table(name = "microsoft_sso_states")
public class MicrosoftSsoState {

    @Id
    @UuidGenerator
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "company_id", nullable = false)
    private UUID companyId;

    @Column(name = "state", nullable = false, unique = true)
    private String state;

    @Column(name = "nonce", nullable = false)
    private String nonce;

    @Column(name = "code_verifier", nullable = false)
    private String codeVerifier;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public MicrosoftSsoState() {}

    public UUID getId() { return id; }
    public void setId(UUID i) { this.id = i; }
    public UUID getCompanyId() { return companyId; }
    public void setCompanyId(UUID c) { this.companyId = c; }
    public String getState() { return state; }
    public void setState(String s) { this.state = s; }
    public String getNonce() { return nonce; }
    public void setNonce(String n) { this.nonce = n; }
    public String getCodeVerifier() { return codeVerifier; }
    public void setCodeVerifier(String c) { this.codeVerifier = c; }
    public String getClientId() { return clientId; }
    public void setClientId(String c) { this.clientId = c; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant e) { this.expiresAt = e; }
    public Instant getUsedAt() { return usedAt; }
    public void setUsedAt(Instant u) { this.usedAt = u; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant c) { this.createdAt = c; }
}
