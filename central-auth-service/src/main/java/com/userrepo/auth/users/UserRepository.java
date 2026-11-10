package com.userrepo.auth.users;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID>, JpaSpecificationExecutor<User> {

    /** Resolve by companyCode + username (Section 3). Never authenticate by username alone. */
    @Query("""
            select u from User u
            join Company c on c.id = u.companyId
            where lower(c.companyCode) = lower(:companyCode)
              and u.normalizedUsername = lower(:username)
            """)
    Optional<User> findByCompanyCodeAndUsername(@Param("companyCode") String companyCode,
                                                @Param("username") String username);

    Optional<User> findByCompanyIdAndNormalizedUsername(UUID companyId, String normalizedUsername);

    List<User> findByCompanyId(UUID companyId);

    @Query("select count(u) > 0 from User u where u.companyId = :companyId and u.normalizedUsername = :username")
    boolean existsByCompanyIdAndNormalizedUsername(@Param("companyId") UUID companyId,
                                                   @Param("username") String username);

    @Query("select u from User u where u.companyId = :companyId and lower(u.email) = lower(:email)")
    Optional<User> findByCompanyIdAndEmailIgnoreCase(@Param("companyId") UUID companyId,
                                                      @Param("email") String email);

    List<User> findByCompanyIdAndCompanyAdmin(UUID companyId, boolean isCompanyAdmin);
}
