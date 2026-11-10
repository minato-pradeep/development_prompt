package com.userrepo.auth.platform;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface PlatformLoginChallengeRepository extends JpaRepository<PlatformLoginChallenge, UUID> {

    @Query("""
            select c from PlatformLoginChallenge c
            where c.tokenHash = :tokenHash
              and c.usedAt is null
              and c.expiresAt > current_timestamp
            """)
    Optional<PlatformLoginChallenge> findValidByTokenHash(@Param("tokenHash") String tokenHash);
}
