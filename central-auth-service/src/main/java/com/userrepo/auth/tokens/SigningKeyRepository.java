package com.userrepo.auth.tokens;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface SigningKeyRepository extends JpaRepository<SigningKey, String> {

    List<SigningKey> findByStatusIn(List<String> statuses);

    @Query("select k from SigningKey k where k.status = 'ACTIVE'")
    List<SigningKey> findActive();
}
