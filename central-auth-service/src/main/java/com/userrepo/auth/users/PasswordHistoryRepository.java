package com.userrepo.auth.users;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.UUID;

public interface PasswordHistoryRepository extends JpaRepository<PasswordHistory, UUID> {

    @Query("select h from PasswordHistory h where h.userId = :uid order by h.createdAt desc")
    List<PasswordHistory> findRecentByUserId(@Param("uid") UUID userId);
}
