package com.userrepo.auth.platform;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface PlatformSessionRepository extends JpaRepository<PlatformSession, UUID> {

    Optional<PlatformSession> findBySidAndRevokedAtIsNull(UUID sid);

    List<PlatformSession> findByPlatformAdminIdAndRevokedAtIsNull(UUID platformAdminId);

    @Modifying
    @Query("""
            update PlatformSession s set s.revokedAt = :now
            where s.platformAdminId = :adminId and s.revokedAt is null
            """)
    int revokeAllByAdminId(@Param("adminId") UUID adminId, @Param("now") Instant now);
}
