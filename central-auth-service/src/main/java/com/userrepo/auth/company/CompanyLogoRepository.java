package com.userrepo.auth.company;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface CompanyLogoRepository extends JpaRepository<CompanyLogo, UUID> {
    Optional<CompanyLogo> findByCompanyId(UUID companyId);
    void deleteByCompanyId(UUID companyId);
}
