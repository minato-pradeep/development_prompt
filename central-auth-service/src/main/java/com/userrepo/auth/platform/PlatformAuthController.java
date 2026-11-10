package com.userrepo.auth.platform;

import com.userrepo.auth.common.ApiResponse;
import com.userrepo.auth.common.TraceIds;
import com.userrepo.auth.platform.dto.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Platform (Super Admin) authentication endpoints (Section 16).
 * These are distinct from tenant authentication. Platform tokens carry a
 * different issuer scope and audience and are never accepted by tenant APIs.
 *
 * <p>All platform endpoints live under {@code /api/v1/platform/auth/}.
 */
@RestController
@RequestMapping("/api/v1/platform/auth")
@Tag(name = "Platform Auth", description = "Super Admin authentication and TOTP management")
public class PlatformAuthController {

    private final PlatformAuthService authService;

    public PlatformAuthController(PlatformAuthService authService) {
        this.authService = authService;
    }

    /** POST /api/v1/platform/auth/login — public (Section 16). */
    @PostMapping("/login")
    @Operation(summary = "Super Admin login (public)")
    public ResponseEntity<ApiResponse<PlatformLoginResponse>> login(
            @Valid @RequestBody PlatformLoginRequest request,
            HttpServletRequest http) {
        PlatformLoginResponse result = authService.login(
                request.username(), request.password(), ipAddress(http));
        return ResponseEntity.ok(ApiResponse.ok(result, TraceIds.current()));
    }

    /** POST /api/v1/platform/auth/totp/setup — requires ONBOARDING challenge. */
    @PostMapping("/totp/setup")
    @Operation(summary = "Start TOTP enrollment (onboarding challenge required)")
    public ResponseEntity<ApiResponse<PlatformTotpSetupResponse>> setupTotp(
            @RequestHeader("X-Challenge-Token") String challengeToken) {
        PlatformTotpSetupResponse result = authService.setupTotp(challengeToken);
        return ResponseEntity.ok(ApiResponse.ok(result, TraceIds.current()));
    }

    /** POST /api/v1/platform/auth/totp/activate — completes TOTP enrollment, returns tokens + recovery codes. */
    @PostMapping("/totp/activate")
    @Operation(summary = "Activate TOTP (complete enrollment)")
    public ResponseEntity<ApiResponse<PlatformTotpActivateResponse>> activateTotp(
            @Valid @RequestBody PlatformTotpActivateRequest request) {
        PlatformTotpActivateResponse result = authService.activateTotp(
                request.challengeToken(), request.totpCode());
        return ResponseEntity.ok(ApiResponse.ok(result, TraceIds.current()));
    }

    /** POST /api/v1/platform/auth/totp/verify — verifies TOTP at login, returns full token pair. */
    @PostMapping("/totp/verify")
    @Operation(summary = "Verify TOTP at login")
    public ResponseEntity<ApiResponse<TokenPairResponse>> verifyTotp(
            @Valid @RequestBody PlatformTotpVerifyRequest request,
            HttpServletRequest http) {
        TokenPairResponse result = authService.verifyTotp(
                request.challengeToken(), request.totpCode(), ipAddress(http));
        return ResponseEntity.ok(ApiResponse.ok(result, TraceIds.current()));
    }

    /** POST /api/v1/platform/auth/refresh — rotate refresh token. */
    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token")
    public ResponseEntity<ApiResponse<TokenPairResponse>> refresh(
            @Valid @RequestBody PlatformRefreshRequest request,
            HttpServletRequest http) {
        TokenPairResponse result = authService.refresh(request.refreshToken(), ipAddress(http));
        return ResponseEntity.ok(ApiResponse.ok(result, TraceIds.current()));
    }

    /** POST /api/v1/platform/auth/logout — revokes current session. */
    @PostMapping("/logout")
    @Operation(summary = "Logout (revoke current session)")
    public ResponseEntity<ApiResponse<Void>> logout(
            @Valid @RequestBody PlatformRefreshRequest request,
            HttpServletRequest http) {
        authService.logout(request.refreshToken(), ipAddress(http));
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    private static String ipAddress(HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            return xff.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
