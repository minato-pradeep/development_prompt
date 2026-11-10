package com.userrepo.auth.platform;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface PlatformAdminTotpRepository extends JpaRepository<PlatformAdminTotp, UUID> {

    Optional<PlatformAdminTotp> findByPlatformAdminId(UUID platformAdminId);

    /**
     * Atomically updates last_accepted_step ONLY if the supplied step is strictly
     * greater than the current value (or the current value is null). Returns 1 on
     * success, 0 if the step is already accepted (replay detected). Section 6.
     */
    @Modifying
    @Query(value = """
            UPDATE platform_admin_totp
               SET last_accepted_step = :step, updated_at = now()
             WHERE platform_admin_id = :adminId
               AND (last_accepted_step IS NULL OR last_accepted_step < :step)
            """, nativeQuery = true)
    int acceptStep(@Param("adminId") UUID adminId, @Param("step") long step);
}
