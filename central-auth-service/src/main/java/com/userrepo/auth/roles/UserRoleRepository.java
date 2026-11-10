package com.userrepo.auth.roles;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface UserRoleRepository extends JpaRepository<UserRoleEntity, UserRoleEntity.UserRoleId> {

    @Query("select ur from UserRoleEntity ur where ur.id.userId = :uid")
    List<UserRoleEntity> findByUserId(@Param("uid") UUID userId);

    @Modifying
    @Query("delete from UserRoleEntity ur where ur.id.userId = :uid")
    void deleteAllByUserId(@Param("uid") UUID userId);
}
