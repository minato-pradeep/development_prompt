package com.userrepo.auth.users;

import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.company.CompanyAuthSettingsRepository;
import com.userrepo.auth.company.CompanyRepository;
import com.userrepo.auth.company.CompanySettingsRepository;
import com.userrepo.auth.config.AppProperties;
import com.userrepo.auth.crypto.Argon2PasswordHasher;
import com.userrepo.auth.notification.NotificationService;
import com.userrepo.auth.permissions.PermissionRepository;
import com.userrepo.auth.roles.RolePermissionRepository;
import com.userrepo.auth.roles.RoleRepository;
import com.userrepo.auth.roles.UserRoleRepository;
import com.userrepo.auth.users.dto.CreateUserRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for UserManagementService (Section 23):
 * test 7 (Company Admin creates users),
 * test 8 (duplicate usernames rejected within company),
 * test 9 (same username allowed in different companies).
 */
@ExtendWith(MockitoExtension.class)
class UserManagementServiceTest {

    @Mock UserRepository             userRepo;
    @Mock UserSessionRepository      sessions;
    @Mock RefreshTokenRepository     refreshTokens;
    @Mock PasswordHistoryRepository  pwHistory;
    @Mock UserRoleRepository         userRoles;
    @Mock RoleRepository             roles;
    @Mock RolePermissionRepository   rolePerms;
    @Mock PermissionRepository       permissions;
    @Mock CompanyRepository          companies;
    @Mock CompanySettingsRepository  companySettings;
    @Mock CompanyAuthSettingsRepository authSettings;
    @Mock NotificationService        notifications;
    @Mock AuditLogService            audit;

    private UserManagementService service;
    private final Argon2PasswordHasher hasher = new Argon2PasswordHasher();
    private final UUID companyA = UUID.randomUUID();
    private final UUID companyB = UUID.randomUUID();

    @BeforeEach
    void setUp() {
        AppProperties props = new AppProperties(
                new AppProperties.Tokens("http://localhost:8081", "http://localhost:8081/platform",
                        900, 900, 43200, 1800, 259200, 86400, 1209600, 2592000, 604800, true),
                new AppProperties.Password(12, 5, 5, false, 259200),
                new AppProperties.Totp(30, 6, "HmacSHA1", 1, 10),
                new AppProperties.RateLimit("postgres"),
                new AppProperties.Bootstrap("X"),
                new AppProperties.Encryption(new AppProperties.Encryption.TotpSecret("K","KID")),
                new AppProperties.Logo(5_242_880L, 1024, 1024, List.of("image/png")));

        service = new UserManagementService(userRepo, sessions, refreshTokens, pwHistory,
                userRoles, roles, rolePerms, permissions, companies, companySettings,
                authSettings, hasher, notifications, audit, props);

        AuditLogService.AuditEntryBuilder builder =
                mock(AuditLogService.AuditEntryBuilder.class, RETURNS_SELF);
        lenient().when(audit.builder(any())).thenReturn(builder);
        lenient().when(userRepo.save(any())).thenAnswer(i -> i.getArgument(0));
        lenient().when(companySettings.findByCompanyId(any())).thenReturn(Optional.empty());
        lenient().when(authSettings.findByCompanyId(any())).thenReturn(Optional.empty());
    }

    // -------------------------------------------------------------------------
    // Test 7: Company Admin creates a user
    // -------------------------------------------------------------------------
    @Test
    void createUser_validRequest_createsUser() {
        when(userRepo.existsByCompanyIdAndNormalizedUsername(companyA, "jdoe")).thenReturn(false);

        User created = service.createUser(companyA,
                new CreateUserRequest("jdoe","jdoe@test.com",null,"John","Doe",null,null,null,null),
                UUID.randomUUID());

        assertThat(created.getUsername()).isEqualTo("jdoe");
        assertThat(created.getCompanyId()).isEqualTo(companyA);
        assertThat(created.getPasswordHash()).startsWith("$argon2id$");
        assertThat(created.isMustChangePassword()).isTrue();
    }

    // -------------------------------------------------------------------------
    // Test 8: Duplicate usernames rejected within a company
    // -------------------------------------------------------------------------
    @Test
    void createUser_duplicateWithinCompany_throwsUsernameTaken() {
        when(userRepo.existsByCompanyIdAndNormalizedUsername(companyA, "jdoe")).thenReturn(true);

        assertThatThrownBy(() -> service.createUser(companyA,
                new CreateUserRequest("jdoe","j@t.com",null,null,null,null,null,null,null),
                UUID.randomUUID()))
                .isInstanceOf(AuthException.class)
                .satisfies(e -> assertThat(((AuthException) e).code())
                        .isEqualTo(AuthErrorCode.USERNAME_TAKEN));
    }

    // -------------------------------------------------------------------------
    // Test 9: Same username is allowed in different companies
    // -------------------------------------------------------------------------
    @Test
    void createUser_sameUsernameInDifferentCompany_succeeds() {
        // jdoe exists in companyA but NOT in companyB.
        when(userRepo.existsByCompanyIdAndNormalizedUsername(companyB, "jdoe")).thenReturn(false);

        User created = service.createUser(companyB,
                new CreateUserRequest("jdoe","jdoe@b.com",null,null,null,null,null,null,null),
                UUID.randomUUID());

        assertThat(created.getCompanyId()).isEqualTo(companyB);
    }

    // -------------------------------------------------------------------------
    // Cross-company access rejected
    // -------------------------------------------------------------------------
    @Test
    void getUser_wrongCompany_throwsCrossTenantDenied() {
        UUID wrongCompany = UUID.randomUUID();
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setCompanyId(companyA);

        when(userRepo.findById(user.getId())).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.getUser(wrongCompany, user.getId()))
                .isInstanceOf(AuthException.class)
                .satisfies(e -> assertThat(((AuthException) e).code())
                        .isEqualTo(AuthErrorCode.CROSS_TENANT_DENIED));
    }

    // -------------------------------------------------------------------------
    // Privilege escalation — cannot assign roles to self
    // -------------------------------------------------------------------------
    @Test
    void assignRoles_toSelf_throwsPrivilegeEscalation() {
        UUID actorId = UUID.randomUUID();
        User actor = new User();
        actor.setId(actorId);
        actor.setCompanyId(companyA);
        when(userRepo.findById(actorId)).thenReturn(Optional.of(actor));

        assertThatThrownBy(() ->
                service.assignRoles(companyA, actorId, List.of(UUID.randomUUID()), actorId))
                .isInstanceOf(AuthException.class)
                .satisfies(e -> assertThat(((AuthException) e).code())
                        .isEqualTo(AuthErrorCode.PRIVILEGE_ESCALATION_DENIED));
    }
}
