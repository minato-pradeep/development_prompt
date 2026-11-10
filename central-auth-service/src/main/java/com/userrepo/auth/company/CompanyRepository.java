package com.userrepo.auth.company;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;
import java.util.UUID;

public interface CompanyRepository extends JpaRepository<Company, UUID> {

    @Query("select c from Company c where lower(c.companyCode) = lower(:code)")
    Optional<Company> findByCompanyCodeIgnoreCase(@Param("code") String code);

    boolean existsByCompanyCodeIgnoreCase(String companyCode);
}
