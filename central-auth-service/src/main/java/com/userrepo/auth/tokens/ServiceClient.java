package com.userrepo.auth.tokens;

import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

/** OAuth2 service client for machine-to-machine client credentials (Section 14). */
@Entity
@Table(name = "service_clients")
public class ServiceClient {

    @Id
    @UuidGenerator
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "client_id", nullable = false, unique = true)
    private String clientId;

    @Column(name = "display_name", nullable = false)
    private String displayName;

    @Column(name = "secret_hash")
    private String secretHash;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public ServiceClient() {}

    public UUID getId() { return id; }
    public void setId(UUID i) { this.id = i; }
    public String getClientId() { return clientId; }
    public void setClientId(String c) { this.clientId = c; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String d) { this.displayName = d; }
    public String getSecretHash() { return secretHash; }
    public void setSecretHash(String s) { this.secretHash = s; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean e) { this.enabled = e; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant c) { this.createdAt = c; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant u) { this.updatedAt = u; }
}
