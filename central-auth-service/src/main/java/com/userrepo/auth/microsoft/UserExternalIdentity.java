package com.userrepo.auth.microsoft;

import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

/** Explicit user → Microsoft identity mapping. Never auto-linked by email (Section 9). */
@Entity
@Table(name = "user_external_identities")
public class UserExternalIdentity {

    @Id
    @UuidGenerator
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "company_id", nullable = false)
    private UUID companyId;

    @Column(name = "provider", nullable = false)
    private String provider = "MICROSOFT";

    @Column(name = "tid", nullable = false)
    private String tid;   // Entra tenant ID

    @Column(name = "oid", nullable = false)
    private String oid;   // Entra object ID

    @Column(name = "email")
    private String email;

    @Column(name = "display_name")
    private String displayName;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public UserExternalIdentity() {}

    public UUID getId() { return id; }
    public void setId(UUID i) { this.id = i; }
    public UUID getUserId() { return userId; }
    public void setUserId(UUID u) { this.userId = u; }
    public UUID getCompanyId() { return companyId; }
    public void setCompanyId(UUID c) { this.companyId = c; }
    public String getProvider() { return provider; }
    public void setProvider(String p) { this.provider = p; }
    public String getTid() { return tid; }
    public void setTid(String t) { this.tid = t; }
    public String getOid() { return oid; }
    public void setOid(String o) { this.oid = o; }
    public String getEmail() { return email; }
    public void setEmail(String e) { this.email = e; }
    public String getDisplayName() { return displayName; }
    public void setDisplayName(String d) { this.displayName = d; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant c) { this.createdAt = c; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant u) { this.updatedAt = u; }
}
