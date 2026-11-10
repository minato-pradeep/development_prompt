package com.userrepo.auth.platform;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PlatformRefreshTokenRepository extends JpaRepository<PlatformRefreshToken, UUID> {

    Optional<PlatformRefreshToken> findByTokenHashAndRevokedAtIsNull(String tokenHash);

    List<PlatformRefreshToken> findByFamilyIdAndRevokedAtIsNull(UUID familyId);

    @Modifying
    @Query("""
            update PlatformRefreshToken t set t.revokedAt = :now, t.revokedReason = :reason
            where t.familyId = :familyId and t.revokedAt is null
            """)
    int revokeFamilyById(@Param("familyId") UUID familyId,
                         @Param("now") Instant now,
                         @Param("reason") String reason);

    @Modifying
    @Query("""
            update PlatformRefreshToken t set t.revokedAt = :now, t.revokedReason = 'SESSION_REVOKED'
            where t.sessionId = :sessionId and t.revokedAt is null
            """)
    int revokeBySessionId(@Param("sessionId") UUID sessionId, @Param("now") Instant now);

    @Modifying
    @Query("""
            update PlatformRefreshToken t set t.revokedAt = :now, t.revokedReason = 'ADMIN_REVOKED_ALL'
            where t.platformAdminId = :adminId and t.revokedAt is null
            """)
    int revokeAllByAdminId(@Param("adminId") UUID adminId, @Param("now") Instant now);
}
