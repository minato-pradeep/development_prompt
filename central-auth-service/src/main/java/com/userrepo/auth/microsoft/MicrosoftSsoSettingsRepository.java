package com.userrepo.auth.microsoft;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface MicrosoftSsoSettingsRepository extends JpaRepository<MicrosoftSsoSettings, UUID> {
    Optional<MicrosoftSsoSettings> findByCompanyId(UUID companyId);
}
