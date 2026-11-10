package com.userrepo.auth.users;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface TotpRecoveryCodeRepository extends JpaRepository<TotpRecoveryCode, UUID> {

    @Query("select c from TotpRecoveryCode c where c.userId = :uid and c.usedAt is null")
    List<TotpRecoveryCode> findUnusedByUserId(@Param("uid") UUID userId);

    @Modifying
    @Query("delete from TotpRecoveryCode c where c.userId = :uid")
    void deleteAllByUserId(@Param("uid") UUID userId);
}
