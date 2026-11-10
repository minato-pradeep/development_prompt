package com.userrepo.auth.platform;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface PlatformAdminRepository extends JpaRepository<PlatformAdmin, UUID> {

    Optional<PlatformAdmin> findByUsername(String username);

    @Query("select p from PlatformAdmin p where lower(p.username) = lower(:username)")
    Optional<PlatformAdmin> findByUsernameCaseInsensitive(@Param("username") String username);

    boolean existsByStatus(String status);

    long countByStatus(String status);
}
