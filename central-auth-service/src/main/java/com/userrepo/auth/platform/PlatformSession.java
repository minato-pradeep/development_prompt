package com.userrepo.auth.platform;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

/** Platform (Super Admin) session. {@code sid} is placed in the JWT (Section 13). */
@Entity
@Table(name = "platform_sessions")
public class PlatformSession {

    @Id
    @UuidGenerator
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "platform_admin_id", nullable = false)
    private UUID platformAdminId;

    @Column(name = "sid", nullable = false)
    private UUID sid;

    @Column(name = "session_version", nullable = false)
    private long sessionVersion;

    @Column(name = "ip_address")
    private String ipAddress;

    @Column(name = "user_agent")
    private String userAgent;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    public PlatformSession() {
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }
    public UUID getPlatformAdminId() { return platformAdminId; }
    public void setPlatformAdminId(UUID platformAdminId) { this.platformAdminId = platformAdminId; }
    public UUID getSid() { return sid; }
    public void setSid(UUID sid) { this.sid = sid; }
    public long getSessionVersion() { return sessionVersion; }
    public void setSessionVersion(long sessionVersion) { this.sessionVersion = sessionVersion; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    public String getUserAgent() { return userAgent; }
    public void setUserAgent(String userAgent) { this.userAgent = userAgent; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getLastSeenAt() { return lastSeenAt; }
    public void setLastSeenAt(Instant lastSeenAt) { this.lastSeenAt = lastSeenAt; }
    public Instant getRevokedAt() { return revokedAt; }
    public void setRevokedAt(Instant revokedAt) { this.revokedAt = revokedAt; }
}
