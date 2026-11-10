package com.userrepo.auth.microsoft;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface InternalAuthCodeRepository extends JpaRepository<InternalAuthCode, UUID> {

    @Query("select c from InternalAuthCode c where c.codeHash = :hash and c.usedAt is null and c.expiresAt > current_timestamp")
    Optional<InternalAuthCode> findValidByCodeHash(@Param("hash") String hash);
}
