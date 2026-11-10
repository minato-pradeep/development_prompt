package com.userrepo.auth.authentication;

import com.userrepo.auth.authentication.dto.*;
import com.userrepo.auth.common.ApiResponse;
import com.userrepo.auth.common.TraceIds;
import com.userrepo.auth.tokens.JwtClaims;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Tenant authentication endpoints (Section 16).
 * Public endpoints: login, totp/*, forgot-password, reset-password, refresh, logout.
 * Authenticated endpoints: change-password, step-up, logout-all, recovery-codes/regenerate.
 */
@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Authentication", description = "Tenant login, TOTP, tokens and password management")
public class TenantAuthController {

    private final TenantAuthService authService;

    public TenantAuthController(TenantAuthService authService) {
        this.authService = authService;
    }

    /** POST /api/v1/auth/login */
    @PostMapping("/login")
    @Operation(summary = "Login with company code, username and password (public)")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest req, HttpServletRequest http) {
        LoginResponse result = authService.login(req, ip(http));
        return ResponseEntity.ok(ApiResponse.ok(result, TraceIds.current()));
    }

    /** POST /api/v1/auth/totp/setup */
    @PostMapping("/totp/setup")
    @Operation(summary = "Start TOTP enrollment (onboarding challenge required)")
    public ResponseEntity<ApiResponse<TotpSetupResponse>> setupTotp(
            @RequestHeader("X-Challenge-Token") String challengeToken) {
        return ResponseEntity.ok(ApiResponse.ok(authService.setupTotp(challengeToken), TraceIds.current()));
    }

    /** POST /api/v1/auth/totp/activate */
    @PostMapping("/totp/activate")
    @Operation(summary = "Activate TOTP and complete enrollment")
    public ResponseEntity<ApiResponse<TotpActivateResponse>> activateTotp(
            @Valid @RequestBody TotpActivateRequest req, HttpServletRequest http) {
        return ResponseEntity.ok(ApiResponse.ok(authService.activateTotp(req, ip(http)), TraceIds.current()));
    }

    /** POST /api/v1/auth/totp/verify */
    @PostMapping("/totp/verify")
    @Operation(summary = "Verify TOTP code at login")
    public ResponseEntity<ApiResponse<TokenResponse>> verifyTotp(
            @Valid @RequestBody TotpVerifyRequest req, HttpServletRequest http) {
        return ResponseEntity.ok(ApiResponse.ok(authService.verifyTotp(req, ip(http)), TraceIds.current()));
    }

    /** POST /api/v1/auth/totp/recovery-codes/regenerate (authenticated) */
    @PostMapping("/totp/recovery-codes/regenerate")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Regenerate recovery codes (requires fresh TOTP)")
    public ResponseEntity<ApiResponse<List<String>>> regenerateCodes(
            @Valid @RequestBody StepUpRequest req,
            @AuthenticationPrincipal Jwt jwt, HttpServletRequest http) {
        UUID userId = UUID.fromString(jwt.getSubject());
        List<String> codes = authService.regenerateRecoveryCodes(userId, req.totpCode(), ip(http));
        return ResponseEntity.ok(ApiResponse.ok(codes, TraceIds.current()));
    }

    /** POST /api/v1/auth/step-up (authenticated) */
    @PostMapping("/step-up")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Step-up authentication (fresh TOTP for sensitive actions)")
    public ResponseEntity<ApiResponse<TokenResponse>> stepUp(
            @Valid @RequestBody StepUpRequest req,
            @AuthenticationPrincipal Jwt jwt, HttpServletRequest http) {
        UUID userId = UUID.fromString(jwt.getSubject());
        return ResponseEntity.ok(ApiResponse.ok(authService.stepUp(userId, req.totpCode(), ip(http)), TraceIds.current()));
    }

    /** POST /api/v1/auth/change-password (onboarding or authenticated) */
    @PostMapping("/change-password")
    @Operation(summary = "Change password (onboarding challenge or authenticated)")
    public ResponseEntity<ApiResponse<LoginResponse>> changePassword(
            @Valid @RequestBody ChangePasswordRequest req, HttpServletRequest http) {
        return ResponseEntity.ok(ApiResponse.ok(authService.changePasswordOnboarding(req, ip(http)), TraceIds.current()));
    }

    /** POST /api/v1/auth/forgot-password (public) */
    @PostMapping("/forgot-password")
    @Operation(summary = "Request a password reset link (public, anti-enumeration)")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(
            @Valid @RequestBody ForgotPasswordRequest req, HttpServletRequest http) {
        authService.forgotPassword(req, ip(http));
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    /** POST /api/v1/auth/reset-password (public) */
    @PostMapping("/reset-password")
    @Operation(summary = "Reset password with single-use token (public)")
    public ResponseEntity<ApiResponse<Void>> resetPassword(
            @Valid @RequestBody ResetPasswordRequest req, HttpServletRequest http) {
        authService.resetPassword(req, ip(http));
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    /** POST /api/v1/auth/refresh (public) */
    @PostMapping("/refresh")
    @Operation(summary = "Rotate refresh token")
    public ResponseEntity<ApiResponse<TokenResponse>> refresh(
            @Valid @RequestBody RefreshRequest req, HttpServletRequest http) {
        return ResponseEntity.ok(ApiResponse.ok(authService.refresh(req, ip(http)), TraceIds.current()));
    }

    /** POST /api/v1/auth/logout (public — accepts refresh token) */
    @PostMapping("/logout")
    @Operation(summary = "Logout current session")
    public ResponseEntity<ApiResponse<Void>> logout(
            @Valid @RequestBody RefreshRequest req, HttpServletRequest http) {
        authService.logout(req.refreshToken(), ip(http));
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    /** POST /api/v1/auth/logout-all (authenticated) */
    @PostMapping("/logout-all")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Logout all sessions for the current user")
    public ResponseEntity<ApiResponse<Void>> logoutAll(
            @AuthenticationPrincipal Jwt jwt, HttpServletRequest http) {
        UUID userId = UUID.fromString(jwt.getSubject());
        authService.logoutAll(userId, ip(http));
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    /** GET /api/v1/auth/sessions (authenticated) */
    @GetMapping("/sessions")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "List active sessions for current user")
    public ResponseEntity<ApiResponse<List<com.userrepo.auth.users.UserSession>>> getSessions(
            @AuthenticationPrincipal Jwt jwt) {
        UUID userId = UUID.fromString(jwt.getSubject());
        // Sessions service delegated to Phase 4 user management
        return ResponseEntity.ok(ApiResponse.ok(List.of(), TraceIds.current()));
    }

    /** DELETE /api/v1/auth/sessions/{id} (authenticated) */
    @DeleteMapping("/sessions/{id}")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Revoke a specific session")
    public ResponseEntity<ApiResponse<Void>> revokeSession(
            @PathVariable UUID id,
            @AuthenticationPrincipal Jwt jwt, HttpServletRequest http) {
        UUID userId = UUID.fromString(jwt.getSubject());
        // Full implementation in Phase 4
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    private static String ip(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        return (xff != null && !xff.isBlank()) ? xff.split(",")[0].trim() : req.getRemoteAddr();
    }
}
