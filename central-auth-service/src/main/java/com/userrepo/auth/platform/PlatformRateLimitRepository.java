package com.userrepo.auth.platform;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface PlatformRateLimitRepository extends JpaRepository<PlatformRateLimitCounter, UUID> {

    Optional<PlatformRateLimitCounter> findByBucketKey(String bucketKey);

    /**
     * Upsert-increment: insert a new counter or increment the existing one within
     * the same window. Returns the new count. Section 20.
     */
    @Modifying
    @Query(value = """
            INSERT INTO platform_rate_limit_counters (id, bucket_key, count, window_start)
            VALUES (gen_random_uuid(), :key, 1, now())
            ON CONFLICT (bucket_key) DO UPDATE
               SET count = CASE
                              WHEN platform_rate_limit_counters.window_start < :windowCutoff
                              THEN 1
                              ELSE platform_rate_limit_counters.count + 1
                           END,
                   window_start = CASE
                                    WHEN platform_rate_limit_counters.window_start < :windowCutoff
                                    THEN now()
                                    ELSE platform_rate_limit_counters.window_start
                                  END
            """, nativeQuery = true)
    void upsertIncrement(@Param("key") String key, @Param("windowCutoff") Instant windowCutoff);

    @Modifying
    @Query(value = """
            UPDATE platform_rate_limit_counters
               SET locked_until = :lockedUntil
             WHERE bucket_key = :key
            """, nativeQuery = true)
    void setLockUntil(@Param("key") String key, @Param("lockedUntil") Instant lockedUntil);

    @Modifying
    @Query(value = """
            UPDATE platform_rate_limit_counters
               SET count = 0, window_start = now(), locked_until = null
             WHERE bucket_key = :key
            """, nativeQuery = true)
    void reset(@Param("key") String key);
}
