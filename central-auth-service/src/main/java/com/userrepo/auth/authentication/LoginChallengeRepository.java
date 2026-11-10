package com.userrepo.auth.authentication;

import com.userrepo.auth.users.LoginChallenge;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface LoginChallengeRepository extends JpaRepository<LoginChallenge, UUID> {

    @Query("""
            select c from LoginChallenge c
            where c.tokenHash = :hash
              and c.usedAt is null
              and c.expiresAt > current_timestamp
            """)
    Optional<LoginChallenge> findValidByTokenHash(@Param("hash") String hash);
}
