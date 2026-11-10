package com.userrepo.auth.users;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHashAndRevokedAtIsNull(String tokenHash);

    @Modifying
    @Query("update RefreshToken t set t.revokedAt = :now, t.revokedReason = :reason where t.familyId = :fid and t.revokedAt is null")
    int revokeFamily(@Param("fid") UUID familyId, @Param("now") Instant now, @Param("reason") String reason);

    @Modifying
    @Query("update RefreshToken t set t.revokedAt = :now, t.revokedReason = 'SESSION_REVOKED' where t.sessionId = :sid and t.revokedAt is null")
    int revokeBySession(@Param("sid") UUID sessionId, @Param("now") Instant now);

    @Modifying
    @Query("update RefreshToken t set t.revokedAt = :now, t.revokedReason = 'USER_REVOKED_ALL' where t.userId = :uid and t.revokedAt is null")
    int revokeAllByUser(@Param("uid") UUID userId, @Param("now") Instant now);

    @Modifying
    @Query("update RefreshToken t set t.revokedAt = :now, t.revokedReason = 'COMPANY_DEACTIVATED' where t.companyId = :cid and t.revokedAt is null")
    int revokeAllByCompany(@Param("cid") UUID companyId, @Param("now") Instant now);
}
