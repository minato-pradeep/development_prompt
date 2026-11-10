package com.userrepo.auth.platform;

import com.userrepo.auth.audit.AuditEventType;
import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.common.ApiResponse;
import com.userrepo.auth.common.TraceIds;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.company.CompanyAuthSettings;
import com.userrepo.auth.company.CompanyAuthSettingsRepository;
import com.userrepo.auth.company.dto.CompanyResponse;
import com.userrepo.auth.crypto.Argon2PasswordHasher;
import com.userrepo.auth.tokens.JwtClaims;
import com.userrepo.auth.users.User;
import com.userrepo.auth.users.UserRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * Super Admin management of Company Admin accounts (Section 4, 16).
 * Endpoints: reset password, unlock, view auth settings, MFA recovery.
 */
@RestController
@RequestMapping("/api/v1/platform/companies/{companyId}")
@PreAuthorize("hasRole('SUPER_ADMIN')")
@Tag(name = "Platform", description = "Super Admin company admin management")
public class PlatformAdminManagementController {

    private final UserRepository                 users;
    private final CompanyAuthSettingsRepository  authSettings;
    private final Argon2PasswordHasher           hasher;
    private final AuditLogService                audit;
    private final SecureRandom                   random = new SecureRandom();

    public PlatformAdminManagementController(UserRepository users,
                                              CompanyAuthSettingsRepository authSettings,
                                              Argon2PasswordHasher hasher,
                                              AuditLogService audit) {
        this.users        = users;
        this.authSettings = authSettings;
        this.hasher       = hasher;
        this.audit        = audit;
    }

    /** POST /api/v1/platform/companies/{id}/admin/reset-password */
    @PostMapping("/admin/reset-password")
    @Operation(summary = "Super Admin resets the Company Admin password")
    public ResponseEntity<ApiResponse<String>> resetAdminPassword(
            @PathVariable UUID companyId,
            @AuthenticationPrincipal Jwt jwt) {
        UUID actorId = UUID.fromString(jwt.getSubject());
        User admin = findCompanyAdmin(companyId);

        byte[] bytes = new byte[18];
        random.nextBytes(bytes);
        String plain = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        admin.setPasswordHash(hasher.encode(plain));
        admin.setMustChangePassword(true);
        // Super Admin reset does NOT disable existing TOTP (Section 18).
        admin.setSessionVersion(admin.getSessionVersion() + 1);
        users.save(admin);

        audit.builder(AuditEventType.USER_PASSWORD_RESET)
                .actor("PLATFORM_ADMIN", actorId).company(companyId)
                .target("USER", admin.getId()).result("SUCCESS").record();

        // Return plaintext once — never logged, never emailed.
        return ResponseEntity.ok(ApiResponse.ok(plain, TraceIds.current()));
    }

    /** POST /api/v1/platform/companies/{id}/admin/unlock */
    @PostMapping("/admin/unlock")
    @Operation(summary = "Super Admin unlocks the Company Admin account")
    public ResponseEntity<ApiResponse<Void>> unlockAdmin(
            @PathVariable UUID companyId,
            @AuthenticationPrincipal Jwt jwt) {
        UUID actorId = UUID.fromString(jwt.getSubject());
        User admin = findCompanyAdmin(companyId);
        admin.setLockedUntil(null);
        admin.setFailedLoginCount(0);
        if ("LOCKED".equals(admin.getStatus())) admin.setStatus("ACTIVE");
        users.save(admin);
        audit.builder(AuditEventType.USER_UNLOCKED)
                .actor("PLATFORM_ADMIN", actorId).company(companyId)
                .target("USER", admin.getId()).result("SUCCESS").record();
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    /** GET /api/v1/platform/companies/{id}/auth-settings */
    @GetMapping("/auth-settings")
    @Operation(summary = "View company auth settings (read-only, for support)")
    public ResponseEntity<ApiResponse<CompanyAuthSettings>> authSettings(
            @PathVariable UUID companyId) {
        CompanyAuthSettings settings = authSettings.findByCompanyId(companyId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND));
        return ResponseEntity.ok(ApiResponse.ok(settings, TraceIds.current()));
    }

    /** POST /api/v1/platform/companies/{id}/admin/mfa-recovery */
    @PostMapping("/admin/mfa-recovery")
    @Operation(summary = "Initiate controlled Company Admin MFA recovery (Section 18)")
    public ResponseEntity<ApiResponse<String>> mfaRecovery(
            @PathVariable UUID companyId,
            @AuthenticationPrincipal Jwt jwt) {
        UUID actorId = UUID.fromString(jwt.getSubject());
        User admin = findCompanyAdmin(companyId);
        // Full MFA recovery flow (Section 18): invalidate old TOTP + force re-enrollment.
        admin.setTotpEnabled(false);
        admin.setMustEnrollTotp(true);
        admin.setSessionVersion(admin.getSessionVersion() + 1);
        users.save(admin);
        audit.builder(AuditEventType.MFA_RECOVERY)
                .actor("PLATFORM_ADMIN", actorId).company(companyId)
                .target("USER", admin.getId()).result("SUCCESS").record();
        return ResponseEntity.ok(ApiResponse.ok(
                "MFA recovery initiated; admin must re-enroll TOTP at next login",
                TraceIds.current()));
    }

    private User findCompanyAdmin(UUID companyId) {
        return users.findByCompanyIdAndCompanyAdmin(companyId, true).stream().findFirst()
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND,
                        "No Company Admin found for this company"));
    }
}
