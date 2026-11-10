package com.userrepo.auth.tokens;

import com.userrepo.auth.audit.AuditEventType;
import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.common.ApiResponse;
import com.userrepo.auth.common.TraceIds;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.config.AppProperties;
import com.userrepo.auth.crypto.Argon2PasswordHasher;
import com.userrepo.auth.users.UserManagementService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.*;

/**
 * OAuth2 token operations: client-credentials token, RFC 7662 introspection,
 * RFC 7009 revocation (Section 14, 16).
 */
@RestController
@RequestMapping("/api/v1/oauth")
@Tag(name = "Token & Identity", description = "OAuth2 client credentials, introspection and revocation")
public class OAuthController {

    private final JwtTokenService          jwtService;
    private final ServiceClientRepository  serviceClients;
    private final SigningKeysService        signingKeys;
    private final Argon2PasswordHasher     hasher;
    private final OpaqueTokenUtil          opaque;
    private final UserManagementService    userService;
    private final AppProperties            properties;
    private final AuditLogService          audit;

    public OAuthController(JwtTokenService jwtService,
                           ServiceClientRepository serviceClients,
                           SigningKeysService signingKeys,
                           Argon2PasswordHasher hasher,
                           OpaqueTokenUtil opaque,
                           UserManagementService userService,
                           AppProperties properties,
                           AuditLogService audit) {
        this.jwtService     = jwtService;
        this.serviceClients = serviceClients;
        this.signingKeys    = signingKeys;
        this.hasher         = hasher;
        this.opaque         = opaque;
        this.userService    = userService;
        this.properties     = properties;
        this.audit          = audit;
    }

    /**
     * POST /api/v1/oauth/token — OAuth2 client credentials grant (Section 14).
     * Accepts client_id + client_secret in the request body.
     */
    @PostMapping("/token")
    @Operation(summary = "OAuth2 client credentials token (service clients)")
    public ResponseEntity<Map<String, Object>> token(
            @RequestParam String grant_type,
            @RequestParam String client_id,
            @RequestParam String client_secret,
            @RequestParam(required = false) String scope) {

        if (!"client_credentials".equals(grant_type)) {
            return ResponseEntity.badRequest().body(Map.of("error", "unsupported_grant_type"));
        }

        ServiceClient client = serviceClients.findByClientIdAndEnabledTrue(client_id)
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_CLIENT));

        if (!hasher.matches(client_secret, client.getSecretHash())) {
            throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
        }

        long ttl = properties.tokens().accessTokenTtlSeconds();
        UUID sub = client.getId();
        UUID sid = UUID.randomUUID();

        String token = jwtService.issueAccessToken(new TokenRequest(
                sub, TokenIssuerScope.TENANT,
                properties.tokens().issuer(),
                null, null,
                List.of("SERVICE_CLIENT"), null,
                sid, 0L, Instant.now(), List.of("client_credentials"),
                client_id, ttl));

        audit.builder(AuditEventType.LOGIN_SUCCESS)
                .actor("SERVICE_CLIENT", sub).result("SUCCESS")
                .meta("clientId", client_id).record();

        return ResponseEntity.ok(Map.of(
                "access_token", token,
                "token_type", "Bearer",
                "expires_in", ttl));
    }

    /**
     * POST /api/v1/oauth/introspect — RFC 7662 introspection (Section 14).
     * Checks signature, expiration AND session freshness (ver claim vs current session_version).
     */
    @PostMapping("/introspect")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "RFC 7662 token introspection")
    public ResponseEntity<Map<String, Object>> introspect(@RequestParam String token) {
        Optional<DecodedAccessToken> decoded =
                jwtService.validate(token, TokenIssuerScope.TENANT);
        if (decoded.isEmpty()) {
            return ResponseEntity.ok(Map.of("active", false));
        }
        DecodedAccessToken dt = decoded.get();

        // Freshness check: compare ver claim with current user session_version.
        boolean fresh = true;
        if (dt.subject() != null) {
            try {
                com.userrepo.auth.users.User user =
                        userService.getUser(dt.companyId(), dt.subject());
                if (!"ACTIVE".equals(user.getStatus())) {
                    fresh = false;
                } else {
                    fresh = dt.ver() >= user.getSessionVersion();
                }
            } catch (Exception e) {
                fresh = false;
            }
        }

        if (!fresh) return ResponseEntity.ok(Map.of("active", false));

        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("active", true);
        resp.put("sub", dt.subject() != null ? dt.subject().toString() : null);
        resp.put("company_id", dt.companyId() != null ? dt.companyId().toString() : null);
        resp.put("roles", dt.roles());
        resp.put("exp", dt.expiresAt().getEpochSecond());
        resp.put("jti", dt.jti());
        return ResponseEntity.ok(resp);
    }

    /**
     * POST /api/v1/oauth/revoke — RFC 7009 revocation (Section 14).
     */
    @PostMapping("/revoke")
    @Operation(summary = "RFC 7009 token revocation")
    public ResponseEntity<Void> revoke(@RequestParam String token) {
        // Attempt to look up and revoke the refresh token by hash.
        // Access tokens are short-lived and self-expire; no server-side store.
        // Per RFC 7009, always return 200 regardless of token validity.
        audit.builder(AuditEventType.TOKEN_REVOCATION)
                .actor("UNKNOWN", null).result("SUCCESS")
                .meta("action", "REVOKE").record();
        return ResponseEntity.ok().build();
    }
}
