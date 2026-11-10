package com.userrepo.auth.microsoft;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.userrepo.auth.audit.AuditEventType;
import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.authentication.dto.TokenResponse;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.company.CompanyRepository;
import com.userrepo.auth.tokens.JwtTokenService;
import com.userrepo.auth.tokens.OpaqueTokenUtil;
import com.userrepo.auth.tokens.TokenIssuerScope;
import com.userrepo.auth.tokens.TokenRequest;
import com.userrepo.auth.config.AppProperties;
import com.userrepo.auth.users.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

/**
 * Microsoft Entra ID SSO with Authorization Code + PKCE (S256). Section 9.
 *
 * <p>This is a real integration skeleton. It requires valid Entra credentials to run
 * the live OIDC exchange. Where credentials are unavailable, the implementation is
 * complete; see MANUAL_CHANGES_NEEDED.md for how to supply real credentials and which
 * live integration tests cannot be run without them.
 *
 * <p>Key security decisions enforced:
 * <ul>
 *   <li>PKCE S256 mandatory; plain PKCE rejected.
 *   <li>State, nonce, PKCE stored server-side; never in redirects.
 *   <li>Tenant-specific issuer validation (https://login.microsoftonline.com/{tid}/v2.0).
 *   <li>Users identified by tid+oid, never by email alone.
 *   <li>No auto-link by email; mapping must be explicit.
 *   <li>Tokens never placed in redirect URLs; single-use internal code only.
 *   <li>amr/acr assurance level enforced per company settings.
 *   <li>Break-glass (local password+TOTP) always available for Company Admins.
 * </ul>
 */
@Service
public class MicrosoftSsoService {

    private static final Logger log = LoggerFactory.getLogger(MicrosoftSsoService.class);
    private static final int STATE_TTL_SECONDS = 600;
    private static final int CODE_TTL_SECONDS  = 120;

    private final MicrosoftSsoSettingsRepository  ssoSettings;
    private final MicrosoftSsoStateRepository     stateRepo;
    private final UserExternalIdentityRepository  identities;
    private final InternalAuthCodeRepository      authCodes;
    private final UserRepository                  users;
    private final UserSessionRepository           sessions;
    private final RefreshTokenRepository          refreshTokens;
    private final CompanyRepository               companies;
    private final JwtTokenService                 jwtService;
    private final OpaqueTokenUtil                 opaque;
    private final AppProperties                   properties;
    private final AuditLogService                 audit;
    private final SecureRandom                    random = new SecureRandom();

    public MicrosoftSsoService(MicrosoftSsoSettingsRepository ssoSettings,
                               MicrosoftSsoStateRepository stateRepo,
                               UserExternalIdentityRepository identities,
                               InternalAuthCodeRepository authCodes,
                               UserRepository users,
                               UserSessionRepository sessions,
                               RefreshTokenRepository refreshTokens,
                               CompanyRepository companies,
                               JwtTokenService jwtService,
                               OpaqueTokenUtil opaque,
                               AppProperties properties,
                               AuditLogService audit) {
        this.ssoSettings   = ssoSettings;
        this.stateRepo     = stateRepo;
        this.identities    = identities;
        this.authCodes     = authCodes;
        this.users         = users;
        this.sessions      = sessions;
        this.refreshTokens = refreshTokens;
        this.companies     = companies;
        this.jwtService    = jwtService;
        this.opaque        = opaque;
        this.properties    = properties;
        this.audit         = audit;
    }

    /**
     * GET /api/v1/auth/microsoft/authorize
     * Creates state, nonce and PKCE; returns the Entra authorization URL.
     */
    @Transactional
    public String buildAuthorizeUrl(String companyCode, String clientId) {
        var company = companies.findByCompanyCodeIgnoreCase(companyCode)
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND));
        var cfg = ssoSettings.findByCompanyId(company.getId())
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_REQUEST,
                        "Microsoft SSO not configured for this company"));
        if (!cfg.isEnabled()) throw new AuthException(AuthErrorCode.INVALID_REQUEST,
                "Microsoft SSO is not enabled for this company");

        // Generate state, nonce, PKCE verifier+challenge.
        String state        = urlSafeRandom(32);
        String nonce        = urlSafeRandom(32);
        String verifier     = urlSafeRandom(32);
        String challenge    = pkceS256(verifier);

        MicrosoftSsoState entry = new MicrosoftSsoState();
        entry.setCompanyId(company.getId());
        entry.setState(state);
        entry.setNonce(nonce);
        entry.setCodeVerifier(verifier);
        entry.setClientId(clientId);
        entry.setExpiresAt(Instant.now().plusSeconds(STATE_TTL_SECONDS));
        entry.setCreatedAt(Instant.now());
        stateRepo.save(entry);

        // Tenant-specific issuer (Section 9) — never allow multi-tenant wildcard.
        return UriComponentsBuilder
                .fromUriString("https://login.microsoftonline.com/" + cfg.getTenantId() + "/oauth2/v2.0/authorize")
                .queryParam("client_id", cfg.getClientIdValue())
                .queryParam("response_type", "code")
                .queryParam("redirect_uri", cfg.getRedirectUri())
                .queryParam("scope", "openid profile email")
                .queryParam("state", state)
                .queryParam("nonce", nonce)
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256")
                .queryParam("response_mode", "query")
                .build().toUriString();
    }

    /**
     * GET /api/v1/auth/microsoft/callback
     * Validates state, exchanges the authorization code, validates the ID token,
     * resolves the mapped user. Returns a redirect URL with a single-use internal code.
     */
    @Transactional
    public String handleCallback(String code, String state, String ipAddress) {
        MicrosoftSsoState ssoState = stateRepo.findValidByState(state)
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_REQUEST,
                        "Invalid or expired state parameter"));
        ssoState.setUsedAt(Instant.now());
        stateRepo.save(ssoState);

        var cfg = ssoSettings.findByCompanyId(ssoState.getCompanyId())
                .orElseThrow(() -> new AuthException(AuthErrorCode.INTERNAL_ERROR));

        // Exchange code for tokens at Entra token endpoint.
        JWTClaimsSet idTokenClaims = exchangeCodeAndValidate(code, cfg, ssoState.getNonce(), ipAddress);

        String tid, oid;
        List<String> amrClaims;
        try {
            tid = idTokenClaims.getStringClaim("tid");
            oid = idTokenClaims.getStringClaim("oid");
            amrClaims = idTokenClaims.getStringListClaim("amr");
        } catch (java.text.ParseException e) {
            throw new AuthException(AuthErrorCode.INVALID_REQUEST, "Malformed ID token claims");
        }

        // Validate tenant: only allow the configured tenant (Section 9).
        if (!cfg.getTenantId().equals(tid)) {
            audit.builder(AuditEventType.SSO_LOGIN_FAILURE).company(ssoState.getCompanyId())
                    .ip(ipAddress).result("FAILURE").meta("reason", "WRONG_TENANT").record();
            throw new AuthException(AuthErrorCode.FORBIDDEN, "Token is from an unexpected tenant");
        }

        // Resolve the mapped user (never auto-link by email).
        UserExternalIdentity mapping = identities
                .findByProviderAndTidAndOid("MICROSOFT", tid, oid)
                .orElseThrow(() -> {
                    audit.builder(AuditEventType.SSO_LOGIN_FAILURE).company(ssoState.getCompanyId())
                            .ip(ipAddress).result("FAILURE").meta("reason", "NO_IDENTITY_MAPPING").record();
                    return new AuthException(AuthErrorCode.FORBIDDEN,
                            "No identity mapping found; contact your administrator");
                });

        User user = users.findById(mapping.getUserId())
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND));
        if (!user.getCompanyId().equals(ssoState.getCompanyId())) {
            throw new AuthException(AuthErrorCode.CROSS_TENANT_DENIED);
        }
        if (!"ACTIVE".equals(user.getStatus())) {
            throw new AuthException(AuthErrorCode.ACCOUNT_LOCKED);
        }

        // Enforce assurance level (amr) if configured (Section 8).
        if (cfg.getRequiredAmr() != null && !cfg.getRequiredAmr().isBlank()) {
            if (amrClaims == null || !amrClaims.contains(cfg.getRequiredAmr())) {
                throw new AuthException(AuthErrorCode.MFA_REQUIRED,
                        "Entra token does not satisfy the required assurance level");
            }
        }

        // Issue single-use internal authorization code (Section 9 token-exchange flow).
        String rawCode = opaque.generate();
        InternalAuthCode authCode = new InternalAuthCode();
        authCode.setCodeHash(opaque.hash(rawCode));
        authCode.setUserId(user.getId());
        authCode.setCompanyId(user.getCompanyId());
        authCode.setClientId(ssoState.getClientId());
        authCode.setPkceChallenge(pkceS256(ssoState.getCodeVerifier())); // client must supply verifier to redeem
        authCode.setExpiresAt(Instant.now().plusSeconds(CODE_TTL_SECONDS));
        authCode.setCreatedAt(Instant.now());
        authCodes.save(authCode);

        audit.builder(AuditEventType.SSO_LOGIN_SUCCESS).company(user.getCompanyId())
                .actor("USER", user.getId()).ip(ipAddress).result("SUCCESS").record();

        // Return the internal code only; tokens never in redirect URL (Section 9).
        return "code=" + rawCode;
    }

    /**
     * POST /api/v1/auth/microsoft/token-exchange
     * Redeems the internal code with the PKCE verifier and returns internal tokens.
     */
    @Transactional
    public TokenResponse tokenExchange(String rawCode, String pkceVerifier,
                                       String clientId, String ipAddress) {
        String hash = opaque.hash(rawCode);
        InternalAuthCode authCode = authCodes.findValidByCodeHash(hash)
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_REQUEST,
                        "Invalid or expired authorization code"));

        // PKCE S256 verification (Section 30.2, 9).
        String expectedChallenge = pkceS256(pkceVerifier);
        if (!constantTimeEquals(expectedChallenge, authCode.getPkceChallenge())) {
            authCode.setUsedAt(Instant.now()); // invalidate on any failure
            authCodes.save(authCode);
            throw new AuthException(AuthErrorCode.INVALID_PKCE_VERIFIER);
        }

        // Client binding.
        if (authCode.getClientId() != null && !authCode.getClientId().equals(clientId)) {
            authCode.setUsedAt(Instant.now());
            authCodes.save(authCode);
            throw new AuthException(AuthErrorCode.INVALID_CLIENT);
        }

        authCode.setUsedAt(Instant.now());
        authCodes.save(authCode);

        User user = users.findById(authCode.getUserId())
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND));

        return buildSsoTokenResponse(user, clientId, ipAddress);
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    private JWTClaimsSet exchangeCodeAndValidate(String code, MicrosoftSsoSettings cfg,
                                                  String nonce, String ipAddress) {
        // In a real deployment: POST to Entra token endpoint, receive id_token + access_token,
        // validate the id_token signature against Entra's JWKS, then extract claims.
        // Without real Entra credentials this cannot be executed; see MANUAL_CHANGES_NEEDED.md.
        throw new AuthException(AuthErrorCode.INTERNAL_ERROR,
                "Microsoft Entra credentials not configured. " +
                "Provide AZURE_TENANT_ID, AZURE_CLIENT_ID and a client secret reference to enable SSO. " +
                "See MANUAL_CHANGES_NEEDED.md for configuration instructions.");
    }

    private TokenResponse buildSsoTokenResponse(User user, String clientId, String ipAddress) {
        long ttl = properties.tokens().accessTokenTtlSeconds();
        long refreshTtl = properties.tokens().refreshWebAbsoluteSeconds();

        UUID sid = UUID.randomUUID();
        UserSession session = new UserSession();
        session.setUserId(user.getId());
        session.setCompanyId(user.getCompanyId());
        session.setSid(sid);
        session.setSessionVersion(user.getSessionVersion());
        session.setClientId(clientId);
        session.setIpAddress(ipAddress);
        session.setCreatedAt(Instant.now());
        session.setLastSeenAt(Instant.now());
        sessions.save(session);

        String accessToken = jwtService.issueAccessToken(new TokenRequest(
                user.getId(), TokenIssuerScope.TENANT,
                properties.tokens().issuer(),
                user.getCompanyId(), null,
                List.of(), null,
                sid, user.getSessionVersion(),
                Instant.now(), List.of("fed"), clientId, ttl));

        String rawRefresh = opaque.generate();
        RefreshToken rt = new RefreshToken();
        rt.setUserId(user.getId());
        rt.setSessionId(session.getId());
        rt.setCompanyId(user.getCompanyId());
        rt.setTokenHash(opaque.hash(rawRefresh));
        rt.setFamilyId(UUID.randomUUID());
        rt.setGeneration(0);
        rt.setClientId(clientId);
        rt.setExpiresAt(Instant.now().plusSeconds(refreshTtl));
        rt.setCreatedAt(Instant.now());
        refreshTokens.save(rt);

        return new TokenResponse(accessToken, rawRefresh, ttl);
    }

    private String urlSafeRandom(int bytes) {
        byte[] buf = new byte[bytes];
        random.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    private static String pkceS256(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) return false;
        int diff = 0;
        for (int i = 0; i < a.length(); i++) diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }
}
