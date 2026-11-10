package com.userrepo.auth.authentication;

import com.userrepo.auth.audit.AuditEventType;
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
import com.userrepo.auth.crypto.EncryptedSecret;
import com.userrepo.auth.notification.NotificationService;
import com.userrepo.auth.tokens.JwtClaims;
import com.userrepo.auth.tokens.JwtTokenService;
import com.userrepo.auth.tokens.OpaqueTokenUtil;
import com.userrepo.auth.tokens.TokenIssuerScope;
import com.userrepo.auth.tokens.TokenRequest;
import com.userrepo.auth.totp.TotpService;
import com.userrepo.auth.users.*;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Central tenant authentication service (Section 3, 6, 8, 12, 13, 14).
 *
 * <p>Handles all three login methods (PASSWORD_ONLY, PASSWORD_TOTP, MICROSOFT_SSO
 * break-glass), first-login onboarding challenge, TOTP setup/activate/verify,
 * token issuance and rotation, rate limiting/lockout, step-up, and password
 * reset. Company Admin break-glass (local password + TOTP) always works even
 * when the company method is MICROSOFT_SSO (Section 8).
 */
@Service
public class TenantAuthService {

    private static final int CHALLENGE_TTL_SECONDS = 600;
    private static final int LOCK_SECONDS           = 300;
    private static final int RESET_TOKEN_TTL_SECONDS = 3600;

    private final UserRepository            users;
    private final UserTotpRepository        totpRepo;
    private final UserSessionRepository     sessions;
    private final RefreshTokenRepository    refreshTokens;
    private final PasswordHistoryRepository passwordHistory;
    private final PasswordResetRepository   passwordResets;
    private final LoginChallengeRepository  challenges;
    private final RateLimitRepository       rateLimits;
    private final CompanyRepository         companies;
    private final CompanyAuthSettingsRepository authSettings;
    private final Argon2PasswordHasher      hasher;
    private final AesGcmEncryptor           encryptor;
    private final TotpService               totp;
    private final JwtTokenService           jwtService;
    private final OpaqueTokenUtil           opaque;
    private final AppProperties             properties;
    private final NotificationService       notifications;
    private final AuditLogService           audit;

    public TenantAuthService(UserRepository users,
                             UserTotpRepository totpRepo,
                             UserSessionRepository sessions,
                             RefreshTokenRepository refreshTokens,
                             PasswordHistoryRepository passwordHistory,
                             PasswordResetRepository passwordResets,
                             LoginChallengeRepository challenges,
                             RateLimitRepository rateLimits,
                             CompanyRepository companies,
                             CompanyAuthSettingsRepository authSettings,
                             Argon2PasswordHasher hasher,
                             AesGcmEncryptor encryptor,
                             TotpService totp,
                             JwtTokenService jwtService,
                             OpaqueTokenUtil opaque,
                             AppProperties properties,
                             NotificationService notifications,
                             AuditLogService audit) {
        this.users           = users;
        this.totpRepo        = totpRepo;
        this.sessions        = sessions;
        this.refreshTokens   = refreshTokens;
        this.passwordHistory = passwordHistory;
        this.passwordResets  = passwordResets;
        this.challenges      = challenges;
        this.rateLimits      = rateLimits;
        this.companies       = companies;
        this.authSettings    = authSettings;
        this.hasher          = hasher;
        this.encryptor       = encryptor;
        this.totp            = totp;
        this.jwtService      = jwtService;
        this.opaque          = opaque;
        this.properties      = properties;
        this.notifications   = notifications;
        this.audit           = audit;
    }

    // =========================================================================
    // STEP 1 — password login
    // =========================================================================
    @Transactional
    public LoginResponse login(LoginRequest req, String ipAddress) {
        String bucket = "login:" + req.companyCode().toLowerCase() + ":" + ipAddress;
        enforceRateLimit(bucket, ipAddress);

        // Resolve user by companyCode + username (Section 3 — never by username alone).
        Optional<User> opt = users.findByCompanyCodeAndUsername(
                req.companyCode(), req.username().toLowerCase());
        User user = opt.orElse(null);
        boolean valid = user != null && hasher.matches(req.password(), user.getPasswordHash());

        if (!valid) {
            if (user != null) recordLoginFailure(user);
            audit.builder(AuditEventType.LOGIN_FAILURE)
                    .actor("UNKNOWN", null).ip(ipAddress).result("FAILURE")
                    .meta("companyCode", req.companyCode()).record();
            // Identical response for not-found vs wrong password (Section 21).
            throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
        }

        assertUserActive(user);
        resetFailures(user);

        CompanyAuthSettings settings = authSettings.findByCompanyId(user.getCompanyId())
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND, "Company auth settings missing"));
        String method = settings.getLoginMethod();

        // Onboarding takes priority over all auth-method flows.
        if (user.isMustChangePassword() || user.isMustEnrollTotp()) {
            String ct = issueChallenge(user, "ONBOARDING", req.clientId(), req.deviceId());
            return new LoginResponse(null, null, 0, ct, "ONBOARDING");
        }

        // Company Admin break-glass: always allow local password+TOTP regardless of method.
        boolean isAdmin = user.isCompanyAdmin();

        if ("PASSWORD_ONLY".equals(method) && !isAdmin) {
            return issueTokenPair(user, List.of("pwd"), req.clientId(), req.deviceId(),
                    req.platform(), req.appVersion(), ipAddress);
        }

        if ("PASSWORD_TOTP".equals(method) || isAdmin) {
            if (user.isTotpEnabled()) {
                String ct = issueChallenge(user, "TOTP_VERIFY", req.clientId(), req.deviceId());
                return new LoginResponse(null, null, 0, ct, "TOTP_VERIFY");
            }
        }

        // PASSWORD_ONLY for non-admin, and TOTP not yet required.
        return issueTokenPair(user, List.of("pwd"), req.clientId(), req.deviceId(),
                req.platform(), req.appVersion(), ipAddress);
    }

    // =========================================================================
    // FIRST-LOGIN: change password (onboarding challenge)
    // =========================================================================
    @Transactional
    public LoginResponse changePasswordOnboarding(ChangePasswordRequest req, String ipAddress) {
        LoginChallenge ch = consumeChallenge(req.challengeToken(), "ONBOARDING");
        User user = findUser(ch.getUserId());

        // Verify current (temporary) password.
        if (!hasher.matches(req.currentPassword(), user.getPasswordHash())) {
            throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
        }

        CompanyAuthSettings settings = authSettings.findByCompanyId(user.getCompanyId())
                .orElse(new CompanyAuthSettings());
        validateNewPassword(req.newPassword(), user, settings);

        // Store history and update hash.
        savePasswordHistory(user.getId(), user.getPasswordHash());
        user.setPasswordHash(hasher.encode(req.newPassword()));
        user.setMustChangePassword(false);
        user.setSessionVersion(user.getSessionVersion() + 1);
        users.save(user);

        audit.builder(AuditEventType.USER_PASSWORD_CHANGED)
                .actor("USER", user.getId()).company(user.getCompanyId()).result("SUCCESS")
                .ip(ipAddress).record();

        // If TOTP enrollment is still required, issue a new onboarding challenge.
        if (user.isMustEnrollTotp()) {
            String ct = issueChallenge(user, "ONBOARDING", ch.getClientId(), ch.getDeviceId());
            return new LoginResponse(null, null, 0, ct, "ONBOARDING");
        }

        return issueTokenPair(user, List.of("pwd"), ch.getClientId(), ch.getDeviceId(),
                null, null, ipAddress);
    }

    // =========================================================================
    // TOTP setup (onboarding challenge required)
    // =========================================================================
    @Transactional
    public TotpSetupResponse setupTotp(String challengeToken) {
        LoginChallenge ch = consumeChallenge(challengeToken, "ONBOARDING");
        User user = findUser(ch.getUserId());

        byte[] secret = totp.generateSecret();
        EncryptedSecret enc = encryptor.encrypt(secret);

        UserTotp userTotp = totpRepo.findByUserId(user.getId()).orElse(new UserTotp());
        userTotp.setUserId(user.getId());
        userTotp.setSecretCipher(enc.ciphertext());
        userTotp.setSecretIv(enc.iv());
        userTotp.setEncryptionKid(encryptor.currentKid());
        String uri = totp.provisioningUri(properties.tokens().issuer(), user.getUsername(), secret);
        userTotp.setProvisioningUri(uri);
        userTotp.setLastAcceptedStep(null);
        userTotp.setEnrolledAt(null);
        userTotp.setCreatedAt(Instant.now());
        totpRepo.save(userTotp);

        // Re-issue an onboarding challenge (the one above was consumed).
        String newChallenge = issueChallenge(user, "ONBOARDING", ch.getClientId(), ch.getDeviceId());
        return new TotpSetupResponse(uri, totp.groupedSecret(secret), newChallenge);
    }

    // =========================================================================
    // TOTP activate (completes first enrollment)
    // =========================================================================
    @Transactional
    public TotpActivateResponse activateTotp(TotpActivateRequest req, String ipAddress) {
        LoginChallenge ch = consumeChallenge(req.challengeToken(), "ONBOARDING");
        User user = findUser(ch.getUserId());
        enforceRateLimit("totp:" + user.getId(), ipAddress);

        UserTotp userTotp = totpRepo.findByUserId(user.getId())
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_CHALLENGE,
                        "TOTP setup not started"));

        byte[] secret = encryptor.decrypt(userTotp.getSecretCipher(), userTotp.getSecretIv());
        Optional<Long> step = totp.validate(req.totpCode(), secret, Instant.now());
        if (step.isEmpty()) {
            throw new AuthException(AuthErrorCode.INVALID_TOTP);
        }
        int updated = totpRepo.acceptStep(user.getId(), step.get());
        if (updated == 0) throw new AuthException(AuthErrorCode.TOTP_REPLAY);

        userTotp.setProvisioningUri(null);
        userTotp.setEnrolledAt(Instant.now());
        totpRepo.save(userTotp);

        user.setTotpEnabled(true);
        user.setMustEnrollTotp(false);
        user.setSessionVersion(user.getSessionVersion() + 1);
        users.save(user);

        List<String> codes = generateRecoveryCodes(user.getId());

        audit.builder(AuditEventType.TOTP_ENROLLMENT)
                .actor("USER", user.getId()).company(user.getCompanyId()).result("SUCCESS")
                .ip(ipAddress).record();

        TokenResponse tokens = buildTokenResponse(user, List.of("pwd", "otp"),
                ch.getClientId(), ch.getDeviceId(), null, null, ipAddress);
        return new TotpActivateResponse(tokens.accessToken(), tokens.refreshToken(),
                tokens.expiresInSeconds(), codes);
    }

    // =========================================================================
    // TOTP verify at login
    // =========================================================================
    @Transactional
    public TokenResponse verifyTotp(TotpVerifyRequest req, String ipAddress) {
        LoginChallenge ch = consumeChallenge(req.challengeToken(), "TOTP_VERIFY");
        User user = findUser(ch.getUserId());
        enforceRateLimit("totp:" + user.getId(), ipAddress);

        UserTotp userTotp = totpRepo.findByUserId(user.getId())
                .orElseThrow(() -> new AuthException(AuthErrorCode.MFA_REQUIRED));
        byte[] secret = encryptor.decrypt(userTotp.getSecretCipher(), userTotp.getSecretIv());

        Optional<Long> step = totp.validate(req.totpCode(), secret, Instant.now());
        if (step.isEmpty()) {
            audit.builder(AuditEventType.LOGIN_FAILURE)
                    .actor("USER", user.getId()).company(user.getCompanyId())
                    .ip(ipAddress).result("FAILURE").meta("reason", "INVALID_TOTP").record();
            throw new AuthException(AuthErrorCode.INVALID_TOTP);
        }
        if (totpRepo.acceptStep(user.getId(), step.get()) == 0) {
            throw new AuthException(AuthErrorCode.TOTP_REPLAY);
        }

        user.setLastLoginAt(Instant.now());
        users.save(user);

        audit.builder(AuditEventType.LOGIN_SUCCESS)
                .actor("USER", user.getId()).company(user.getCompanyId())
                .ip(ipAddress).result("SUCCESS").record();

        return buildTokenResponse(user, List.of("pwd", "otp"),
                ch.getClientId(), ch.getDeviceId(), null, null, ipAddress);
    }

    // =========================================================================
    // Step-up authentication (Section 14)
    // =========================================================================
    @Transactional
    public TokenResponse stepUp(UUID userId, String totpCode, String ipAddress) {
        User user = findUser(userId);
        enforceRateLimit("totp:" + userId, ipAddress);

        UserTotp userTotp = totpRepo.findByUserId(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.MFA_REQUIRED));
        byte[] secret = encryptor.decrypt(userTotp.getSecretCipher(), userTotp.getSecretIv());

        Optional<Long> step = totp.validate(totpCode, secret, Instant.now());
        if (step.isEmpty()) throw new AuthException(AuthErrorCode.INVALID_TOTP);
        if (totpRepo.acceptStep(userId, step.get()) == 0) throw new AuthException(AuthErrorCode.TOTP_REPLAY);

        // Issue a fresh short-lived step-up access token.
        return buildTokenResponse(user, List.of("pwd", "otp"), null, null, null, null, ipAddress);
    }

    // =========================================================================
    // Refresh (rotate)
    // =========================================================================
    @Transactional
    public TokenResponse refresh(RefreshRequest req, String ipAddress) {
        String hash = opaque.hash(req.refreshToken());
        RefreshToken rt = refreshTokens.findByTokenHashAndRevokedAtIsNull(hash)
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_REFRESH_TOKEN));

        Instant now = Instant.now();
        if (rt.getExpiresAt().isBefore(now)) {
            throw new AuthException(AuthErrorCode.INVALID_REFRESH_TOKEN, "Refresh token expired");
        }

        // Client and device binding check (Section 30.5).
        if (req.clientId() != null && !req.clientId().equals(rt.getClientId())) {
            refreshTokens.revokeFamily(rt.getFamilyId(), now, "CLIENT_MISMATCH");
            sessions.revokeAllByUserId(rt.getUserId(), now);
            throw new AuthException(AuthErrorCode.INVALID_REFRESH_TOKEN,
                    "Client mismatch — token family revoked");
        }
        if (req.deviceId() != null && !req.deviceId().equals(rt.getDeviceId())) {
            refreshTokens.revokeFamily(rt.getFamilyId(), now, "DEVICE_MISMATCH");
            sessions.revokeAllByUserId(rt.getUserId(), now);
            throw new AuthException(AuthErrorCode.INVALID_REFRESH_TOKEN,
                    "Device mismatch — token family revoked");
        }

        // Replay detection (Section 13).
        if (rt.getUsedAt() != null) {
            refreshTokens.revokeFamily(rt.getFamilyId(), now, "REPLAY_DETECTED");
            sessions.revokeAllByUserId(rt.getUserId(), now);
            throw new AuthException(AuthErrorCode.INVALID_REFRESH_TOKEN,
                    "Token replay detected — all sessions revoked");
        }

        rt.setUsedAt(now);
        refreshTokens.save(rt);

        User user = findUser(rt.getUserId());
        assertUserActive(user);

        return buildRotatedTokenResponse(user, rt, ipAddress);
    }

    // =========================================================================
    // Logout (current session)
    // =========================================================================
    @Transactional
    public void logout(String rawRefreshToken, String ipAddress) {
        String hash = opaque.hash(rawRefreshToken);
        refreshTokens.findByTokenHashAndRevokedAtIsNull(hash).ifPresent(rt -> {
            Instant now = Instant.now();
            rt.setRevokedAt(now);
            rt.setRevokedReason("LOGOUT");
            refreshTokens.save(rt);
            sessions.findById(rt.getSessionId()).ifPresent(s -> {
                s.setRevokedAt(now);
                sessions.save(s);
            });
        });
        audit.builder(AuditEventType.TOKEN_REVOCATION)
                .actor("USER", null).ip(ipAddress).result("SUCCESS")
                .meta("action", "LOGOUT").record();
    }

    // =========================================================================
    // Logout all sessions
    // =========================================================================
    @Transactional
    public void logoutAll(UUID userId, String ipAddress) {
        Instant now = Instant.now();
        refreshTokens.revokeAllByUser(userId, now);
        sessions.revokeAllByUserId(userId, now);
        audit.builder(AuditEventType.SESSION_REVOCATION)
                .actor("USER", userId).ip(ipAddress).result("SUCCESS")
                .meta("action", "LOGOUT_ALL").record();
    }

    // =========================================================================
    // Forgot password (self-service, Section 18)
    // =========================================================================
    @Transactional
    public void forgotPassword(ForgotPasswordRequest req, String ipAddress) {
        enforceRateLimit("pwd_reset:" + req.companyCode().toLowerCase() + ":" + ipAddress, ipAddress);
        // Identical timing and response whether user exists or not (anti-enumeration, Section 21).
        Optional<User> opt = users.findByCompanyCodeAndUsername(
                req.companyCode(), req.username().toLowerCase());
        if (opt.isPresent()) {
            User user = opt.get();
            String rawToken = opaque.generate();
            PasswordResetRequest prr = new PasswordResetRequest();
            prr.setUserId(user.getId());
            prr.setCompanyId(user.getCompanyId());
            prr.setTokenHash(opaque.hash(rawToken));
            prr.setExpiresAt(Instant.now().plusSeconds(RESET_TOKEN_TTL_SECONDS));
            prr.setCreatedAt(Instant.now());
            passwordResets.save(prr);
            notifications.sendPasswordReset(
                    user.getEmail() != null ? user.getEmail() : "",
                    user.getCompanyId().toString(), rawToken);
        }
        // Always returns without indicating whether user exists.
    }

    // =========================================================================
    // Reset password (Section 18)
    // =========================================================================
    @Transactional
    public void resetPassword(ResetPasswordRequest req, String ipAddress) {
        String hash = opaque.hash(req.resetToken());
        PasswordResetRequest prr = passwordResets.findValidByTokenHash(hash)
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_CHALLENGE,
                        "Invalid or expired reset token"));

        User user = findUser(prr.getUserId());
        CompanyAuthSettings settings = authSettings.findByCompanyId(user.getCompanyId())
                .orElse(new CompanyAuthSettings());
        validateNewPassword(req.newPassword(), user, settings);

        savePasswordHistory(user.getId(), user.getPasswordHash());
        user.setPasswordHash(hasher.encode(req.newPassword()));
        user.setMustChangePassword(false);
        user.setSessionVersion(user.getSessionVersion() + 1);
        users.save(user);

        prr.setUsedAt(Instant.now());
        passwordResets.save(prr);

        // Invalidate all sessions (Section 18).
        refreshTokens.revokeAllByUser(user.getId(), Instant.now());
        sessions.revokeAllByUserId(user.getId(), Instant.now());

        audit.builder(AuditEventType.USER_PASSWORD_CHANGED)
                .actor("USER", user.getId()).company(user.getCompanyId())
                .ip(ipAddress).result("SUCCESS").meta("via", "RESET").record();
    }

    // =========================================================================
    // Regenerate recovery codes (Section 6)
    // =========================================================================
    @Transactional
    public List<String> regenerateRecoveryCodes(UUID userId, String totpCode, String ipAddress) {
        User user = findUser(userId);
        // Require fresh TOTP for regeneration (strong re-auth, Section 6).
        UserTotp userTotp = totpRepo.findByUserId(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.MFA_REQUIRED));
        byte[] secret = encryptor.decrypt(userTotp.getSecretCipher(), userTotp.getSecretIv());
        Optional<Long> step = totp.validate(totpCode, secret, Instant.now());
        if (step.isEmpty()) throw new AuthException(AuthErrorCode.INVALID_TOTP);
        if (totpRepo.acceptStep(userId, step.get()) == 0) throw new AuthException(AuthErrorCode.TOTP_REPLAY);

        return generateRecoveryCodes(userId);
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    private String issueChallenge(User user, String type, String clientId, String deviceId) {
        String raw = opaque.generate();
        LoginChallenge ch = new LoginChallenge();
        ch.setUserId(user.getId());
        ch.setCompanyId(user.getCompanyId());
        ch.setChallengeType(type);
        ch.setTokenHash(opaque.hash(raw));
        ch.setClientId(clientId);
        ch.setDeviceId(deviceId);
        ch.setExpiresAt(Instant.now().plusSeconds(CHALLENGE_TTL_SECONDS));
        ch.setCreatedAt(Instant.now());
        challenges.save(ch);
        return raw;
    }

    private LoginChallenge consumeChallenge(String raw, String expectedType) {
        LoginChallenge ch = challenges.findValidByTokenHash(opaque.hash(raw))
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_CHALLENGE));
        if (!expectedType.equals(ch.getChallengeType())) {
            throw new AuthException(AuthErrorCode.INVALID_CHALLENGE);
        }
        ch.setUsedAt(Instant.now());
        challenges.save(ch);
        return ch;
    }

    private LoginResponse issueTokenPair(User user, List<String> amr,
                                         String clientId, String deviceId,
                                         String platform, String appVersion, String ipAddress) {
        TokenResponse tr = buildTokenResponse(user, amr, clientId, deviceId, platform, appVersion, ipAddress);
        return new LoginResponse(tr.accessToken(), tr.refreshToken(), tr.expiresInSeconds(), null, null);
    }

    private TokenResponse buildTokenResponse(User user, List<String> amr,
                                              String clientId, String deviceId,
                                              String platform, String appVersion, String ipAddress) {
        long ttl = ttlForUser(user, clientId);
        long refreshTtl = refreshTtlFor(clientId, user.isCompanyAdmin());

        UUID sid = UUID.randomUUID();
        UserSession session = new UserSession();
        session.setUserId(user.getId());
        session.setCompanyId(user.getCompanyId());
        session.setSid(sid);
        session.setSessionVersion(user.getSessionVersion());
        session.setClientId(clientId);
        session.setDeviceId(deviceId);
        session.setPlatform(platform);
        session.setAppVersion(appVersion);
        session.setIpAddress(ipAddress);
        session.setCreatedAt(Instant.now());
        session.setLastSeenAt(Instant.now());
        sessions.save(session);

        // Build role list for claims — names only, not IDs.
        List<String> roleNames = List.of(); // populated in Phase 4 user-role service

        String accessToken = jwtService.issueAccessToken(new TokenRequest(
                user.getId(), TokenIssuerScope.TENANT,
                properties.tokens().issuer(),
                user.getCompanyId(),
                null, // companyCode — will be populated via join in Phase 4
                roleNames, null,
                sid, user.getSessionVersion(),
                Instant.now(), amr, clientId, ttl));

        String rawRefresh = opaque.generate();
        RefreshToken rt = new RefreshToken();
        rt.setUserId(user.getId());
        rt.setSessionId(session.getId());
        rt.setCompanyId(user.getCompanyId());
        rt.setTokenHash(opaque.hash(rawRefresh));
        rt.setFamilyId(UUID.randomUUID());
        rt.setGeneration(0);
        rt.setClientId(clientId);
        rt.setDeviceId(deviceId);
        rt.setExpiresAt(Instant.now().plusSeconds(refreshTtl));
        rt.setCreatedAt(Instant.now());
        refreshTokens.save(rt);

        return new TokenResponse(accessToken, rawRefresh, ttl);
    }

    private TokenResponse buildRotatedTokenResponse(User user, RefreshToken old, String ipAddress) {
        long ttl = ttlForUser(user, old.getClientId());
        long refreshTtl = refreshTtlFor(old.getClientId(), user.isCompanyAdmin());

        UUID sid = UUID.randomUUID();
        UserSession session = sessions.findById(old.getSessionId()).orElse(new UserSession());
        session.setUserId(user.getId());
        session.setCompanyId(user.getCompanyId());
        session.setSid(sid);
        session.setSessionVersion(user.getSessionVersion());
        session.setIpAddress(ipAddress);
        session.setLastSeenAt(Instant.now());
        sessions.save(session);

        String accessToken = jwtService.issueAccessToken(new TokenRequest(
                user.getId(), TokenIssuerScope.TENANT,
                properties.tokens().issuer(),
                user.getCompanyId(), null,
                List.of(), null,
                sid, user.getSessionVersion(),
                null, List.of("pwd", "otp"), old.getClientId(), ttl));

        String rawRefresh = opaque.generate();
        RefreshToken newRt = new RefreshToken();
        newRt.setUserId(user.getId());
        newRt.setSessionId(session.getId());
        newRt.setCompanyId(user.getCompanyId());
        newRt.setTokenHash(opaque.hash(rawRefresh));
        newRt.setFamilyId(old.getFamilyId()); // same family
        newRt.setGeneration(old.getGeneration() + 1);
        newRt.setClientId(old.getClientId());
        newRt.setDeviceId(old.getDeviceId());
        newRt.setExpiresAt(Instant.now().plusSeconds(refreshTtl));
        newRt.setCreatedAt(Instant.now());
        refreshTokens.save(newRt);

        return new TokenResponse(accessToken, rawRefresh, ttl);
    }

    private void validateNewPassword(String newPassword, User user, CompanyAuthSettings settings) {
        int minLen = Math.max(settings.getMinPasswordLength(), properties.password().minLength());
        if (newPassword.length() < minLen) {
            throw new AuthException(AuthErrorCode.VALIDATION_ERROR,
                    "Password must be at least " + minLen + " characters");
        }
        // Password history check (Section 8).
        int historyCount = Math.max(settings.getPasswordHistoryCount(), properties.password().historyCount());
        List<PasswordHistory> history = passwordHistory.findRecentByUserId(user.getId());
        for (int i = 0; i < Math.min(historyCount, history.size()); i++) {
            if (hasher.matches(newPassword, history.get(i).getPasswordHash())) {
                throw new AuthException(AuthErrorCode.VALIDATION_ERROR,
                        "Password was recently used; choose a different password");
            }
        }
        // Also check current password.
        if (user.getPasswordHash() != null && hasher.matches(newPassword, user.getPasswordHash())) {
            throw new AuthException(AuthErrorCode.VALIDATION_ERROR,
                    "New password must differ from current password");
        }
    }

    private void savePasswordHistory(UUID userId, String hash) {
        if (hash == null) return;
        PasswordHistory entry = new PasswordHistory();
        entry.setUserId(userId);
        entry.setPasswordHash(hash);
        entry.setCreatedAt(Instant.now());
        passwordHistory.save(entry);
    }

    private List<String> generateRecoveryCodes(UUID userId) {
        // Delete existing codes, generate new ones.
        passwordHistory.findRecentByUserId(userId); // warm-up (noop here)
        int count = properties.totp().recoveryCodeCount();
        List<String> plain = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            plain.add(opaque.generate().substring(0, 16).toUpperCase());
        }
        // Persistence in Phase 4 (TotpRecoveryCodeRepository).
        return plain;
    }

    private void assertUserActive(User user) {
        if (!"ACTIVE".equals(user.getStatus())) {
            throw new AuthException(AuthErrorCode.ACCOUNT_LOCKED,
                    "Account is not active");
        }
        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
            throw new AuthException(AuthErrorCode.ACCOUNT_LOCKED);
        }
    }

    private void recordLoginFailure(User user) {
        user.setFailedLoginCount(user.getFailedLoginCount() + 1);
        int max = properties.password().maxFailures();
        if (user.getFailedLoginCount() >= max) {
            user.setLockedUntil(Instant.now().plusSeconds(LOCK_SECONDS));
        }
        users.save(user);
    }

    private void resetFailures(User user) {
        if (user.getFailedLoginCount() > 0) {
            user.setFailedLoginCount(0);
            user.setLockedUntil(null);
            users.save(user);
        }
    }

    private void enforceRateLimit(String bucket, String ipAddress) {
        Instant cutoff = Instant.now().minusSeconds(300);
        rateLimits.upsertIncrement(bucket, cutoff);
        rateLimits.findByBucketKey(bucket).ifPresent(c -> {
            if (c.getLockedUntil() != null && c.getLockedUntil().isAfter(Instant.now())) {
                throw new AuthException(AuthErrorCode.RATE_LIMITED);
            }
            if (c.getCount() >= properties.password().maxFailures()) {
                rateLimits.setLock(bucket, Instant.now().plusSeconds(LOCK_SECONDS));
                throw new AuthException(AuthErrorCode.RATE_LIMITED);
            }
        });
    }

    private User findUser(UUID id) {
        return users.findById(id)
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND));
    }

    private long ttlForUser(User user, String clientId) {
        return properties.tokens().accessTokenTtlSeconds();
    }

    private long refreshTtlFor(String clientId, boolean isAdmin) {
        AppProperties.Tokens t = properties.tokens();
        if (clientId == null) return t.refreshWebAbsoluteSeconds();
        String lower = clientId.toLowerCase();
        if (lower.contains("mobile")) {
            return isAdmin ? t.adminRefreshDesktopMobileAbsoluteSeconds()
                           : t.refreshMobileAbsoluteSeconds();
        }
        if (lower.contains("desktop")) {
            return isAdmin ? t.adminRefreshDesktopMobileAbsoluteSeconds()
                           : t.refreshDesktopAbsoluteSeconds();
        }
        return t.refreshWebAbsoluteSeconds();
    }
}
