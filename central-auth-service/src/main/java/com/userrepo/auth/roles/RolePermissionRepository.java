package com.userrepo.auth.roles;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface RolePermissionRepository
        extends JpaRepository<RolePermissionEntity, RolePermissionEntity.RolePermissionId> {

    @Query("select rp from RolePermissionEntity rp where rp.id.roleId = :rid")
    List<RolePermissionEntity> findByRoleId(@Param("rid") UUID roleId);

    @Modifying
    @Query("delete from RolePermissionEntity rp where rp.id.roleId = :rid")
    void deleteAllByRoleId(@Param("rid") UUID roleId);
}
