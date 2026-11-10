package com.userrepo.auth.users;

import jakarta.persistence.*;
import org.hibernate.annotations.UuidGenerator;

import java.time.Instant;
import java.util.UUID;

/** Rate-limit counter for tenant login flows (Section 20). PostgreSQL-backed for multi-instance consistency. */
@Entity
@Table(name = "rate_limit_counters")
public class RateLimitCounter {

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

    public RateLimitCounter() {}

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
