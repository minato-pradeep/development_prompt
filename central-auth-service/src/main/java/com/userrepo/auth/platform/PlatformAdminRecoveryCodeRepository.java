package com.userrepo.auth.platform;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface PlatformAdminRecoveryCodeRepository extends JpaRepository<PlatformAdminRecoveryCode, UUID> {

    @Query("select c from PlatformAdminRecoveryCode c where c.platformAdminId = :adminId and c.usedAt is null")
    List<PlatformAdminRecoveryCode> findUnusedByAdminId(@Param("adminId") UUID adminId);

    @Modifying
    @Query("delete from PlatformAdminRecoveryCode c where c.platformAdminId = :adminId")
    void deleteAllByAdminId(@Param("adminId") UUID adminId);
}
