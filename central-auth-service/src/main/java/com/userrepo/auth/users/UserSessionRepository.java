package com.userrepo.auth.users;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserSessionRepository extends JpaRepository<UserSession, UUID> {

    Optional<UserSession> findBySidAndRevokedAtIsNull(UUID sid);

    List<UserSession> findByUserIdAndRevokedAtIsNull(UUID userId);

    List<UserSession> findByCompanyIdAndRevokedAtIsNull(UUID companyId);

    @Modifying
    @Query("update UserSession s set s.revokedAt = :now where s.userId = :userId and s.revokedAt is null")
    int revokeAllByUserId(@Param("userId") UUID userId, @Param("now") Instant now);

    @Modifying
    @Query("update UserSession s set s.lastSeenAt = :now where s.id = :id")
    void touchLastSeen(@Param("id") UUID id, @Param("now") Instant now);

    long countByUserIdAndRevokedAtIsNull(UUID userId);
}
