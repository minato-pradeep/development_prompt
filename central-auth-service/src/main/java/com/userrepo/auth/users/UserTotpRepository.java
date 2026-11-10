package com.userrepo.auth.users;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface UserTotpRepository extends JpaRepository<UserTotp, UUID> {

    Optional<UserTotp> findByUserId(UUID userId);

    /** Atomically accept a TOTP step only if strictly greater than current value. Returns 1 on success, 0 on replay. */
    @Modifying
    @Query(value = """
            UPDATE user_totp
               SET last_accepted_step = :step, updated_at = now()
             WHERE user_id = :userId
               AND (last_accepted_step IS NULL OR last_accepted_step < :step)
            """, nativeQuery = true)
    int acceptStep(@Param("userId") UUID userId, @Param("step") long step);
}
