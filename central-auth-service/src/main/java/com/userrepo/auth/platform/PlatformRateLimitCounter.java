package com.userrepo.auth.platform;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

/**
 * Rate-limit / lockout counter keyed by bucket (e.g. {@code platform_login:<ip>},
 * {@code totp_verify:<admin_id>}). PostgreSQL-backed for multi-instance consistency (Section 20).
 */
@Entity
@Table(name = "platform_rate_limit_counters")
public class PlatformRateLimitCounter {

    @Id
    @UuidGenerator
    @Column(name = "id", updatable = false, nullable = false)
    private UUID id;

    @Column(name = "bucket_key", nullable = false, unique = true)
    private String bucketKey;

    @Column(name = "count", nullable = false)
    private long count;

    @Column(name = "window_start", nullable = false)
    private Instant windowStart;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    public PlatformRateLimitCounter() {
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }
    public String getBucketKey() { return bucketKey; }
    public void setBucketKey(String bucketKey) { this.bucketKey = bucketKey; }
    public long getCount() { return count; }
    public void setCount(long count) { this.count = count; }
    public Instant getWindowStart() { return windowStart; }
    public void setWindowStart(Instant windowStart) { this.windowStart = windowStart; }
    public Instant getLockedUntil() { return lockedUntil; }
    public void setLockedUntil(Instant lockedUntil) { this.lockedUntil = lockedUntil; }
}
