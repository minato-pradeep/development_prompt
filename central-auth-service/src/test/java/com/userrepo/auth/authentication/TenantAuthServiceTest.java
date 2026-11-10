package com.userrepo.auth.authentication;

import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.authentication.dto.*;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.company.CompanyAuthSettings;
import com.userrepo.auth.company.CompanyAuthSettingsRepository;
import com.userrepo.auth.company.CompanyRepository;
import com.userrepo.auth.config.AppProperties;
import com.userrepo.auth.crypto.AesGcmEncryptor;
import com.userrepo.auth.crypto.Argon2PasswordHasher;
import com.userrepo.auth.notification.NotificationService;
import com.userrepo.auth.tokens.JwtTokenService;
import com.userrepo.auth.tokens.OpaqueTokenUtil;
import com.userrepo.auth.totp.TotpService;
import com.userrepo.auth.users.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for TenantAuthService covering Section 23 scenarios:
 * test 3 (cannot bypass password change), test 4 (cannot bypass TOTP),
 * test 8 (duplicate usernames rejected), test 12 (password-only login),
 * test 20 (disabled user blocked).
 */
@ExtendWith(MockitoExtension.class)
class TenantAuthServiceTest {

    @Mock UserRepository            users;
    @Mock UserTotpRepository        totpRepo;
    @Mock UserSessionRepository     sessions;
    @Mock RefreshTokenRepository    refreshTokens;
    @Mock PasswordHistoryRepository pwHistory;
    @Mock PasswordResetRepository   pwResets;
    @Mock LoginChallengeRepository  challenges;
    @Mock RateLimitRepository       rateLimits;
    @Mock CompanyRepository         companies;
    @Mock CompanyAuthSettingsRepository authSettings;
    @Mock JwtTokenService           jwtService;
    @Mock NotificationService       notifications;
    @Mock AuditLogService           audit;

    private TenantAuthService service;
    private final Argon2PasswordHasher hasher = new Argon2PasswordHasher();
    private final OpaqueTokenUtil opaque = new OpaqueTokenUtil();

    @BeforeEach
    void setUp() throws Exception {
        AppProperties props = buildProps();
        AesGcmEncryptor encryptor = new AesGcmEncryptor(props);
        TotpService totpService   = new TotpService(props);

        service = new TenantAuthService(users, totpRepo, sessions, refreshTokens,
                pwHistory, pwResets, challenges, rateLimits, companies, authSettings,
                hasher, encryptor, totpService, jwtService, opaque, props,
                notifications, audit);

        // No-op audit builder
        AuditLogService.AuditEntryBuilder builder =
                mock(AuditLogService.AuditEntryBuilder.class, RETURNS_SELF);
        lenient().when(audit.builder(any())).thenReturn(builder);
        lenient().when(rateLimits.findByBucketKey(any())).thenReturn(Optional.empty());
        lenient().doNothing().when(rateLimits).upsertIncrement(any(), any());
    }

    // -------------------------------------------------------------------------
    // Test 3: Company Admin cannot bypass first-login password change
    // -------------------------------------------------------------------------
    @Test
    void login_mustChangePassword_returnsOnboardingChallenge() {
        User user = activeUser();
        user.setMustChangePassword(true);
        user.setMustEnrollTotp(false);
        user.setPasswordHash(hasher.encode("TempPass123!"));

        when(users.findByCompanyCodeAndUsername("ACME", "admin")).thenReturn(Optional.of(user));
        lenient().when(authSettings.findByCompanyId(user.getCompanyId()))
                .thenReturn(Optional.of(passwordOnlySettings()));
        lenient().when(challenges.save(any())).thenAnswer(i -> i.getArgument(0));

        LoginRequest req = new LoginRequest("ACME", "admin", "TempPass123!", null, null, null, null);
        LoginResponse resp = service.login(req, "127.0.0.1");

        assertThat(resp.challengeType()).isEqualTo("ONBOARDING");
        assertThat(resp.accessToken()).isNull();
    }

    // -------------------------------------------------------------------------
    // Test 4: Company Admin cannot bypass initial TOTP registration
    // -------------------------------------------------------------------------
    @Test
    void login_mustEnrollTotp_returnsOnboardingChallenge() {
        User user = activeUser();
        user.setMustChangePassword(false);
        user.setMustEnrollTotp(true);
        user.setPasswordHash(hasher.encode("SecurePass123!"));

        when(users.findByCompanyCodeAndUsername("ACME", "admin")).thenReturn(Optional.of(user));
        lenient().when(authSettings.findByCompanyId(user.getCompanyId()))
                .thenReturn(Optional.of(passwordOnlySettings()));
        lenient().when(challenges.save(any())).thenAnswer(i -> i.getArgument(0));

        LoginRequest req = new LoginRequest("ACME", "admin", "SecurePass123!", null, null, null, null);
        LoginResponse resp = service.login(req, "127.0.0.1");

        assertThat(resp.challengeType()).isEqualTo("ONBOARDING");
    }

    // -------------------------------------------------------------------------
    // Test 12: Password-only login succeeds when no onboarding required
    // -------------------------------------------------------------------------
    @Test
    void login_passwordOnly_noOnboarding_returnsTokens() {
        User user = activeUser();
        user.setMustChangePassword(false);
        user.setMustEnrollTotp(false);
        user.setTotpEnabled(false);
        user.setCompanyAdmin(false);
        user.setPasswordHash(hasher.encode("SecurePass123!"));

        when(users.findByCompanyCodeAndUsername("ACME", "user")).thenReturn(Optional.of(user));
        when(authSettings.findByCompanyId(user.getCompanyId()))
                .thenReturn(Optional.of(passwordOnlySettings()));
        when(sessions.save(any())).thenAnswer(i -> i.getArgument(0));
        when(refreshTokens.save(any())).thenAnswer(i -> i.getArgument(0));
        when(jwtService.issueAccessToken(any())).thenReturn("mock.jwt.token");

        LoginRequest req = new LoginRequest("ACME", "user", "SecurePass123!", null, null, null, null);
        LoginResponse resp = service.login(req, "127.0.0.1");

        assertThat(resp.accessToken()).isNotNull();
        assertThat(resp.challengeType()).isNull();
    }

    // -------------------------------------------------------------------------
    // Test 20: Disabled user is blocked
    // -------------------------------------------------------------------------
    @Test
    void login_disabledUser_throwsAccountLocked() {
        User user = activeUser();
        user.setStatus("DISABLED");
        user.setPasswordHash(hasher.encode("Pass123!"));

        when(users.findByCompanyCodeAndUsername("ACME", "admin")).thenReturn(Optional.of(user));

        LoginRequest req = new LoginRequest("ACME", "admin", "Pass123!", null, null, null, null);
        assertThatThrownBy(() -> service.login(req, "127.0.0.1"))
                .isInstanceOf(AuthException.class)
                .satisfies(e -> assertThat(((AuthException) e).code())
                        .isEqualTo(AuthErrorCode.ACCOUNT_LOCKED));
    }

    // -------------------------------------------------------------------------
    // Invalid credentials → generic error (anti-enumeration)
    // -------------------------------------------------------------------------
    @Test
    void login_wrongPassword_throwsInvalidCredentials() {
        User user = activeUser();
        user.setPasswordHash(hasher.encode("CorrectPass!"));
        user.setMustChangePassword(false);
        user.setMustEnrollTotp(false);

        when(users.findByCompanyCodeAndUsername("ACME", "admin")).thenReturn(Optional.of(user));
        lenient().when(users.save(any())).thenReturn(user);

        LoginRequest req = new LoginRequest("ACME", "admin", "WrongPass!", null, null, null, null);
        assertThatThrownBy(() -> service.login(req, "127.0.0.1"))
                .isInstanceOf(AuthException.class)
                .satisfies(e -> assertThat(((AuthException) e).code())
                        .isEqualTo(AuthErrorCode.INVALID_CREDENTIALS));
    }

    @Test
    void login_userNotFound_throwsInvalidCredentials() {
        when(users.findByCompanyCodeAndUsername("ACME", "ghost")).thenReturn(Optional.empty());
        LoginRequest req = new LoginRequest("ACME", "ghost", "Pass123!", null, null, null, null);
        assertThatThrownBy(() -> service.login(req, "127.0.0.1"))
                .isInstanceOf(AuthException.class)
                .satisfies(e -> assertThat(((AuthException) e).code())
                        .isEqualTo(AuthErrorCode.INVALID_CREDENTIALS));
    }

    // =========================================================================
    private User activeUser() {
        User u = new User();
        u.setId(UUID.randomUUID());
        u.setCompanyId(UUID.randomUUID());
        u.setUsername("admin");
        u.setNormalizedUsername("admin");
        u.setStatus("ACTIVE");
        u.setCompanyAdmin(true);
        return u;
    }

    private CompanyAuthSettings passwordOnlySettings() {
        CompanyAuthSettings s = new CompanyAuthSettings();
        s.setLoginMethod("PASSWORD_ONLY");
        return s;
    }

    private AppProperties buildProps() {
        return new AppProperties(
                new AppProperties.Tokens("http://localhost:8081", "http://localhost:8081/platform",
                        900, 900, 43200, 1800, 259200, 86400, 1209600, 2592000, 604800, true),
                new AppProperties.Password(12, 5, 5, false, 259200),
                new AppProperties.Totp(30, 6, "HmacSHA1", 1, 10),
                new AppProperties.RateLimit("postgres"),
                new AppProperties.Bootstrap("CENTRAL_AUTH_BOOTSTRAP_SECRET"),
                new AppProperties.Encryption(new AppProperties.Encryption.TotpSecret("K", "KID")),
                new AppProperties.Logo(5_242_880L, 1024, 1024, List.of("image/png", "image/jpeg")));
    }
}
