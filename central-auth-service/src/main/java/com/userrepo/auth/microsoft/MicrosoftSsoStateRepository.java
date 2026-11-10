package com.userrepo.auth.microsoft;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface MicrosoftSsoStateRepository extends JpaRepository<MicrosoftSsoState, UUID> {

    @Query("select s from MicrosoftSsoState s where s.state = :state and s.usedAt is null and s.expiresAt > current_timestamp")
    Optional<MicrosoftSsoState> findValidByState(@Param("state") String state);
}
