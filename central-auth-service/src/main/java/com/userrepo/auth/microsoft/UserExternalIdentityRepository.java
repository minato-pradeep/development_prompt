package com.userrepo.auth.microsoft;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UserExternalIdentityRepository extends JpaRepository<UserExternalIdentity, UUID> {

    /** Globally unique (provider, tid, oid) — Section 9. */
    Optional<UserExternalIdentity> findByProviderAndTidAndOid(String provider, String tid, String oid);

    Optional<UserExternalIdentity> findByUserIdAndProvider(UUID userId, String provider);
}
