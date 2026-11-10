package com.userrepo.auth.microsoft;

import com.userrepo.auth.authentication.dto.TokenResponse;
import com.userrepo.auth.common.ApiResponse;
import com.userrepo.auth.common.TraceIds;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Microsoft SSO endpoints (Section 16, 9).
 * The server manages the OIDC flow; tokens never appear in redirect query parameters.
 */
@RestController
@RequestMapping("/api/v1/auth/microsoft")
@Tag(name = "Microsoft SSO", description = "Entra ID OIDC authorization code + PKCE flow")
public class MicrosoftSsoController {

    private final MicrosoftSsoService ssoService;

    public MicrosoftSsoController(MicrosoftSsoService ssoService) {
        this.ssoService = ssoService;
    }

    /**
     * GET /api/v1/auth/microsoft/authorize?companyCode=ACME&clientId=central-auth-web
     * Returns the Entra authorization URL to redirect the user to.
     */
    @GetMapping("/authorize")
    @Operation(summary = "Get Microsoft Entra authorization URL (public)")
    public ResponseEntity<ApiResponse<String>> authorize(
            @RequestParam String companyCode,
            @RequestParam(required = false) String clientId) {
        String url = ssoService.buildAuthorizeUrl(companyCode, clientId);
        return ResponseEntity.ok(ApiResponse.ok(url, TraceIds.current()));
    }

    /**
     * GET /api/v1/auth/microsoft/callback
     * Entra redirects here after the user authenticates. Returns a single-use
     * internal code only; tokens are never placed in the redirect (Section 9).
     */
    @GetMapping("/callback")
    @Operation(summary = "Entra callback — validates state, exchanges code, returns internal code")
    public ResponseEntity<ApiResponse<String>> callback(
            @RequestParam String code,
            @RequestParam String state,
            HttpServletRequest http) {
        String result = ssoService.handleCallback(code, state, ip(http));
        return ResponseEntity.ok(ApiResponse.ok(result, TraceIds.current()));
    }

    /**
     * POST /api/v1/auth/microsoft/token-exchange
     * Client redeems the internal code with the PKCE verifier and receives
     * internal access + refresh tokens.
     */
    @PostMapping("/token-exchange")
    @Operation(summary = "Exchange internal authorization code for tokens (PKCE required)")
    public ResponseEntity<ApiResponse<TokenResponse>> tokenExchange(
            @RequestParam String code,
            @RequestParam String codeVerifier,
            @RequestParam(required = false) String clientId,
            HttpServletRequest http) {
        TokenResponse tokens = ssoService.tokenExchange(code, codeVerifier, clientId, ip(http));
        return ResponseEntity.ok(ApiResponse.ok(tokens, TraceIds.current()));
    }

    private static String ip(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        return (xff != null && !xff.isBlank()) ? xff.split(",")[0].trim() : req.getRemoteAddr();
    }
}
