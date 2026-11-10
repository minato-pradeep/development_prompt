package com.userrepo.auth.roles;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RoleRepository extends JpaRepository<Role, UUID> {

    List<Role> findByCompanyId(UUID companyId);

    Optional<Role> findByCompanyIdAndName(UUID companyId, String name);

    @Query("select r from Role r where r.companyId = :companyId and r.name = 'COMPANY_ADMIN'")
    Optional<Role> findCompanyAdminRole(@Param("companyId") UUID companyId);
}
