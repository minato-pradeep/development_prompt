package com.userrepo.auth.authentication;

import com.userrepo.auth.users.RateLimitCounter;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RateLimitRepository extends JpaRepository<RateLimitCounter, UUID> {

    Optional<RateLimitCounter> findByBucketKey(String bucketKey);

    @Modifying
    @Query(value = """
            INSERT INTO rate_limit_counters (id, bucket_key, count, window_start)
            VALUES (gen_random_uuid(), :key, 1, now())
            ON CONFLICT (bucket_key) DO UPDATE
               SET count = CASE
                              WHEN rate_limit_counters.window_start < :cutoff THEN 1
                              ELSE rate_limit_counters.count + 1
                           END,
                   window_start = CASE
                                    WHEN rate_limit_counters.window_start < :cutoff THEN now()
                                    ELSE rate_limit_counters.window_start
                                  END
            """, nativeQuery = true)
    void upsertIncrement(@Param("key") String key, @Param("cutoff") Instant cutoff);

    @Modifying
    @Query(value = "UPDATE rate_limit_counters SET locked_until = :until WHERE bucket_key = :key", nativeQuery = true)
    void setLock(@Param("key") String key, @Param("until") Instant until);

    @Modifying
    @Query(value = "UPDATE rate_limit_counters SET count = 0, window_start = now(), locked_until = null WHERE bucket_key = :key", nativeQuery = true)
    void reset(@Param("key") String key);
}
