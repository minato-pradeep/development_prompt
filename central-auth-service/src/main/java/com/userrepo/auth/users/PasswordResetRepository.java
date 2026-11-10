package com.userrepo.auth.users;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface PasswordResetRepository extends JpaRepository<PasswordResetRequest, UUID> {

    @Query("select r from PasswordResetRequest r where r.tokenHash = :hash and r.usedAt is null and r.expiresAt > current_timestamp")
    Optional<PasswordResetRequest> findValidByTokenHash(@Param("hash") String hash);
}
