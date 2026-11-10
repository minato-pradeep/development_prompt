package com.userrepo.auth.platform;

import com.userrepo.auth.audit.AuditEventType;
import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.config.AppProperties;
import com.userrepo.auth.crypto.AesGcmEncryptor;
import com.userrepo.auth.crypto.Argon2PasswordHasher;
import com.userrepo.auth.crypto.EncryptedSecret;
import com.userrepo.auth.platform.dto.*;
import com.userrepo.auth.tokens.JwtTokenService;
import com.userrepo.auth.tokens.OpaqueTokenUtil;
import com.userrepo.auth.tokens.TokenIssuerScope;
import com.userrepo.auth.tokens.TokenRequest;
import com.userrepo.auth.totp.TotpService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Super Admin authentication: login, TOTP setup/activate/verify, refresh, logout (Section 4).
 * Platform tokens use a distinct issuer scope and audience. They are never accepted by tenant
 * APIs and tenant tokens are never accepted by platform APIs.
 */
@Service
public class PlatformAuthService {

    private static final int CHALLENGE_TTL_SECONDS = 600;    // 10 minutes
    private static final int LOCK_SECONDS = 300;             // 5-minute lockout

    private final PlatformAdminRepository admins;
    private final PlatformAdminTotpRepository totpRepo;
    private final PlatformAdminRecoveryCodeRepository recoveryRepo;
    private final PlatformLoginChallengeRepository challenges;
    private final PlatformSessionRepository sessions;
    private final PlatformRefreshTokenRepository refreshTokens;
    private final PlatformRateLimitRepository rateLimits;
    private final Argon2PasswordHasher hasher;
    private final AesGcmEncryptor encryptor;
    private final TotpService totpService;
    private final JwtTokenService jwtService;
    private final OpaqueTokenUtil opaque;
    private final AppProperties properties;
    private final AuditLogService audit;

    public PlatformAuthService(PlatformAdminRepository admins,
                               PlatformAdminTotpRepository totpRepo,
                               PlatformAdminRecoveryCodeRepository recoveryRepo,
                               PlatformLoginChallengeRepository challenges,
                               PlatformSessionRepository sessions,
                               PlatformRefreshTokenRepository refreshTokens,
                               PlatformRateLimitRepository rateLimits,
                               Argon2PasswordHasher hasher,
                               AesGcmEncryptor encryptor,
                               TotpService totpService,
                               JwtTokenService jwtService,
                               OpaqueTokenUtil opaque,
                               AppProperties properties,
                               AuditLogService audit) {
        this.admins = admins;
        this.totpRepo = totpRepo;
        this.recoveryRepo = recoveryRepo;
        this.challenges = challenges;
        this.sessions = sessions;
        this.refreshTokens = refreshTokens;
        this.rateLimits = rateLimits;
        this.hasher = hasher;
        this.encryptor = encryptor;
        this.totpService = totpService;
        this.jwtService = jwtService;
        this.opaque = opaque;
        this.properties = properties;
        this.audit = audit;
    }

    // -------------------------------------------------------------------------
    // Step 1: password login → returns challenge if TOTP/onboarding is needed
    // -------------------------------------------------------------------------
    @Transactional
    public PlatformLoginResponse login(String username, String password, String ipAddress) {
        enforceRateLimit("platform_login:" + ipAddress, ipAddress);

        // Look up by username (case-insensitive). Use identical timing for not-found vs wrong
        // password to prevent username enumeration (Section 21).
        Optional<PlatformAdmin> opt = admins.findByUsernameCaseInsensitive(username);
        PlatformAdmin admin = opt.orElse(null);
        boolean valid = admin != null && hasher.matches(password, admin.getPasswordHash());
        if (!valid) {
            if (admin != null) {
                recordFailure(admin, ipAddress);
            }
            audit.builder(AuditEventType.PLATFORM_LOGIN_FAILURE)
                    .actor("UNKNOWN", null).ip(ipAddress).result("FAILURE")
                    .meta("username", username).record();
            throw new AuthException(AuthErrorCode.INVALID_CREDENTIALS);
        }

        assertNotLocked(admin);
        resetFailureCount(admin);

        // If onboarding incomplete: issue restricted onboarding challenge.
        if (admin.isMustChangePassword() || admin.isMustEnrollTotp()) {
            String challengeToken = issuePlatformChallenge(admin.getId(), "ONBOARDING");
            return new PlatformLoginResponse(null, null, 0, challengeToken, "ONBOARDING");
        }

        // If TOTP is enabled: issue TOTP challenge.
        if (admin.isTotpEnabled()) {
            String challengeToken = issuePlatformChallenge(admin.getId(), "TOTP_VERIFY");
            return new PlatformLoginResponse(null, null, 0, challengeToken, "TOTP_VERIFY");
        }

        // No TOTP enrolled yet (shouldn't reach here after onboarding, but guard).
        throw new AuthException(AuthErrorCode.MFA_REQUIRED, "TOTP enrollment is required");
    }

    // -------------------------------------------------------------------------
    // TOTP setup (onboarding challenge required)
    // -------------------------------------------------------------------------
    @Transactional
    public PlatformTotpSetupResponse setupTotp(String challengeToken) {
        PlatformLoginChallenge challenge = consumeChallenge(challengeToken, "ONBOARDING");
        PlatformAdmin admin = findAdmin(challenge.getPlatformAdminId());

        // Generate and encrypt a fresh TOTP secret.
        byte[] secret = totpService.generateSecret();
        EncryptedSecret enc = encryptor.encrypt(secret);

        PlatformAdminTotp totp = totpRepo.findByPlatformAdminId(admin.getId())
                .orElse(new PlatformAdminTotp());
        totp.setPlatformAdminId(admin.getId());
        totp.setSecretCipher(enc.ciphertext());
        totp.setSecretIv(enc.iv());
        totp.setEncryptionKid(encryptor.currentKid());
        String uri = totpService.provisioningUri(
                properties.tokens().platformIssuer(), admin.getUsername(), secret);
        totp.setProvisioningUri(uri);
        totp.setLastAcceptedStep(null);
        totp.setEnrolledAt(null);
        totp.setCreatedAt(Instant.now());
        totpRepo.save(totp);

        // Reissue an onboarding challenge (this one was consumed).
        String newChallenge = issuePlatformChallenge(admin.getId(), "ONBOARDING");

        return new PlatformTotpSetupResponse(
                uri, totpService.groupedSecret(secret), newChallenge);
        // NOTE: secret plaintext is NOT stored anywhere after this method returns.
    }

    // -------------------------------------------------------------------------
    // TOTP activate (first verification, completes enrollment)
    // -------------------------------------------------------------------------
    @Transactional
    public PlatformTotpActivateResponse activateTotp(String challengeToken, String totpCode) {
        PlatformLoginChallenge challenge = consumeChallenge(challengeToken, "ONBOARDING");
        PlatformAdmin admin = findAdmin(challenge.getPlatformAdminId());
        enforceRateLimit("platform_totp:" + admin.getId(), null);

        PlatformAdminTotp totp = totpRepo.findByPlatformAdminId(admin.getId())
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_CHALLENGE,
                        "TOTP setup not started"));

        byte[] secret = encryptor.decrypt(totp.getSecretCipher(), totp.getSecretIv());
        Optional<Long> step = totpService.validate(totpCode, secret, Instant.now());
        if (step.isEmpty()) {
            audit.builder(AuditEventType.PLATFORM_TOTP_ENROLLMENT)
                    .actor("PLATFORM_ADMIN", admin.getId()).result("FAILURE").record();
            throw new AuthException(AuthErrorCode.INVALID_TOTP);
        }

        int updated = totpRepo.acceptStep(admin.getId(), step.get());
        if (updated == 0) {
            throw new AuthException(AuthErrorCode.TOTP_REPLAY);
        }

        totp.setProvisioningUri(null); // clear URI after activation
        totp.setEnrolledAt(Instant.now());
        totpRepo.save(totp);

        admin.setTotpEnabled(true);
        admin.setMustEnrollTotp(false);
        admin.setMustChangePassword(false);
        admin.setSessionVersion(admin.getSessionVersion() + 1);
        admins.save(admin);

        List<String> plainRecoveryCodes = generateRecoveryCodes(admin.getId());

        audit.builder(AuditEventType.PLATFORM_TOTP_ENROLLMENT)
                .actor("PLATFORM_ADMIN", admin.getId()).result("SUCCESS").record();

        TokenPairResponse tokens = issueTokenPair(admin, List.of("pwd", "otp"), null);
        return new PlatformTotpActivateResponse(
                tokens.accessToken(), tokens.refreshToken(),
                tokens.expiresInSeconds(), plainRecoveryCodes);
    }

    // -------------------------------------------------------------------------
    // TOTP verify at login
    // -------------------------------------------------------------------------
    @Transactional
    public TokenPairResponse verifyTotp(String challengeToken, String totpCode, String ipAddress) {
        PlatformLoginChallenge challenge = consumeChallenge(challengeToken, "TOTP_VERIFY");
        PlatformAdmin admin = findAdmin(challenge.getPlatformAdminId());
        enforceRateLimit("platform_totp:" + admin.getId(), ipAddress);

        PlatformAdminTotp totp = totpRepo.findByPlatformAdminId(admin.getId())
                .orElseThrow(() -> new AuthException(AuthErrorCode.MFA_REQUIRED));
        byte[] secret = encryptor.decrypt(totp.getSecretCipher(), totp.getSecretIv());

        Optional<Long> step = totpService.validate(totpCode, secret, Instant.now());
        if (step.isEmpty()) {
            audit.builder(AuditEventType.PLATFORM_LOGIN_FAILURE)
                    .actor("PLATFORM_ADMIN", admin.getId()).ip(ipAddress).result("FAILURE")
                    .meta("reason", "INVALID_TOTP").record();
            throw new AuthException(AuthErrorCode.INVALID_TOTP);
        }
        int updated = totpRepo.acceptStep(admin.getId(), step.get());
        if (updated == 0) {
            throw new AuthException(AuthErrorCode.TOTP_REPLAY);
        }

        admin.setLastLoginAt(Instant.now());
        admins.save(admin);

        audit.builder(AuditEventType.PLATFORM_LOGIN_SUCCESS)
                .actor("PLATFORM_ADMIN", admin.getId()).ip(ipAddress).result("SUCCESS").record();

        return issueTokenPair(admin, List.of("pwd", "otp"), ipAddress);
    }

    // -------------------------------------------------------------------------
    // Refresh
    // -------------------------------------------------------------------------
    @Transactional
    public TokenPairResponse refresh(String rawRefreshToken, String ipAddress) {
        String hash = opaque.hash(rawRefreshToken);
        PlatformRefreshToken token = refreshTokens.findByTokenHashAndRevokedAtIsNull(hash)
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_REFRESH_TOKEN));

        Instant now = Instant.now();
        if (token.getExpiresAt().isBefore(now)) {
            throw new AuthException(AuthErrorCode.INVALID_REFRESH_TOKEN, "Refresh token expired");
        }
        // Replay detection: if the token was already used, revoke the family.
        if (token.getUsedAt() != null) {
            refreshTokens.revokeFamilyById(token.getFamilyId(), now, "REPLAY_DETECTED");
            sessions.revokeAllByAdminId(token.getPlatformAdminId(), now);
            audit.builder(AuditEventType.PLATFORM_TOKEN_REVOCATION)
                    .actor("SYSTEM", null).target("PLATFORM_ADMIN", token.getPlatformAdminId())
                    .result("FAILURE").meta("reason", "REFRESH_TOKEN_REPLAY").ip(ipAddress).record();
            throw new AuthException(AuthErrorCode.INVALID_REFRESH_TOKEN, "Token replay detected; all sessions revoked");
        }

        // Mark as used.
        token.setUsedAt(now);
        refreshTokens.save(token);

        PlatformAdmin admin = findAdmin(token.getPlatformAdminId());
        assertNotLocked(admin);

        // Issue a rotated pair.
        return issueRotatedTokenPair(admin, token, ipAddress);
    }

    // -------------------------------------------------------------------------
    // Logout
    // -------------------------------------------------------------------------
    @Transactional
    public void logout(String rawRefreshToken, String ipAddress) {
        String hash = opaque.hash(rawRefreshToken);
        refreshTokens.findByTokenHashAndRevokedAtIsNull(hash).ifPresent(t -> {
            Instant now = Instant.now();
            t.setRevokedAt(now);
            t.setRevokedReason("LOGOUT");
            refreshTokens.save(t);
            sessions.findById(t.getSessionId()).ifPresent(s -> {
                s.setRevokedAt(now);
                sessions.save(s);
            });
        });
        audit.builder(AuditEventType.PLATFORM_LOGOUT)
                .actor("PLATFORM_ADMIN", null).ip(ipAddress).result("SUCCESS").record();
    }

    // =========================================================================
    // Private helpers
    // =========================================================================

    private String issuePlatformChallenge(UUID adminId, String type) {
        String raw = opaque.generate();
        PlatformLoginChallenge c = new PlatformLoginChallenge();
        c.setPlatformAdminId(adminId);
        c.setChallengeType(type);
        c.setTokenHash(opaque.hash(raw));
        c.setExpiresAt(Instant.now().plusSeconds(CHALLENGE_TTL_SECONDS));
        c.setCreatedAt(Instant.now());
        challenges.save(c);
        return raw;
    }

    private PlatformLoginChallenge consumeChallenge(String rawToken, String expectedType) {
        String hash = opaque.hash(rawToken);
        PlatformLoginChallenge c = challenges.findValidByTokenHash(hash)
                .orElseThrow(() -> new AuthException(AuthErrorCode.INVALID_CHALLENGE));
        if (!expectedType.equals(c.getChallengeType())) {
            throw new AuthException(AuthErrorCode.INVALID_CHALLENGE);
        }
        c.setUsedAt(Instant.now());
        challenges.save(c);
        return c;
    }

    private TokenPairResponse issueTokenPair(PlatformAdmin admin, List<String> amr, String ipAddress) {
        UUID sid = UUID.randomUUID();
        long ttl = properties.tokens().platformAccessTokenTtlSeconds();
        long refreshTtl = properties.tokens().refreshWebAbsoluteSeconds();

        PlatformSession session = new PlatformSession();
        session.setPlatformAdminId(admin.getId());
        session.setSid(sid);
        session.setSessionVersion(admin.getSessionVersion());
        session.setIpAddress(ipAddress);
        session.setCreatedAt(Instant.now());
        session.setLastSeenAt(Instant.now());
        sessions.save(session);

        String accessToken = jwtService.issueAccessToken(new TokenRequest(
                admin.getId(), TokenIssuerScope.PLATFORM,
                properties.tokens().platformIssuer(),
                null, null,
                List.of("SUPER_ADMIN"), null,
                sid, admin.getSessionVersion(),
                Instant.now(), amr, null, ttl));

        String rawRefresh = opaque.generate();
        PlatformRefreshToken rt = new PlatformRefreshToken();
        rt.setPlatformAdminId(admin.getId());
        rt.setSessionId(session.getId());
        rt.setTokenHash(opaque.hash(rawRefresh));
        rt.setFamilyId(UUID.randomUUID());
        rt.setGeneration(0);
        rt.setExpiresAt(Instant.now().plusSeconds(refreshTtl));
        rt.setCreatedAt(Instant.now());
        refreshTokens.save(rt);

        return new TokenPairResponse(accessToken, rawRefresh, ttl);
    }

    private TokenPairResponse issueRotatedTokenPair(PlatformAdmin admin,
                                                    PlatformRefreshToken old,
                                                    String ipAddress) {
        UUID sid = UUID.randomUUID();
        long ttl = properties.tokens().platformAccessTokenTtlSeconds();
        long refreshTtl = properties.tokens().refreshWebAbsoluteSeconds();

        PlatformSession session = sessions.findById(old.getSessionId()).orElse(null);
        if (session == null) {
            session = new PlatformSession();
            session.setPlatformAdminId(admin.getId());
            session.setCreatedAt(Instant.now());
        }
        session.setSid(sid);
        session.setSessionVersion(admin.getSessionVersion());
        session.setIpAddress(ipAddress);
        session.setLastSeenAt(Instant.now());
        sessions.save(session);

        String accessToken = jwtService.issueAccessToken(new TokenRequest(
                admin.getId(), TokenIssuerScope.PLATFORM,
                properties.tokens().platformIssuer(),
                null, null,
                List.of("SUPER_ADMIN"), null,
                sid, admin.getSessionVersion(),
                null, List.of("pwd", "otp"), null, ttl));

        String rawRefresh = opaque.generate();
        PlatformRefreshToken newRt = new PlatformRefreshToken();
        newRt.setPlatformAdminId(admin.getId());
        newRt.setSessionId(session.getId());
        newRt.setTokenHash(opaque.hash(rawRefresh));
        newRt.setFamilyId(old.getFamilyId());   // same family
        newRt.setGeneration(old.getGeneration() + 1);
        newRt.setExpiresAt(Instant.now().plusSeconds(refreshTtl));
        newRt.setCreatedAt(Instant.now());
        refreshTokens.save(newRt);

        return new TokenPairResponse(accessToken, rawRefresh, ttl);
    }

    private List<String> generateRecoveryCodes(UUID adminId) {
        recoveryRepo.deleteAllByAdminId(adminId);
        int count = properties.totp().recoveryCodeCount();
        List<String> plain = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            String code = opaque.generate().substring(0, 16).toUpperCase();
            PlatformAdminRecoveryCode rc = new PlatformAdminRecoveryCode();
            rc.setPlatformAdminId(adminId);
            rc.setCodeHash(opaque.hash(code));
            rc.setCreatedAt(Instant.now());
            recoveryRepo.save(rc);
            plain.add(code);
        }
        return plain;
    }

    private PlatformAdmin findAdmin(UUID id) {
        return admins.findById(id)
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND, "Platform admin not found"));
    }

    private void enforceRateLimit(String bucket, String ipAddress) {
        Instant windowCutoff = Instant.now().minusSeconds(300);
        rateLimits.upsertIncrement(bucket, windowCutoff);
        rateLimits.findByBucketKey(bucket).ifPresent(c -> {
            if (c.getLockedUntil() != null && c.getLockedUntil().isAfter(Instant.now())) {
                throw new AuthException(AuthErrorCode.RATE_LIMITED);
            }
            int max = properties.password().maxFailures();
            if (c.getCount() >= max) {
                Instant lockUntil = Instant.now().plusSeconds(LOCK_SECONDS);
                rateLimits.setLockUntil(bucket, lockUntil);
                throw new AuthException(AuthErrorCode.RATE_LIMITED);
            }
        });
    }

    private void assertNotLocked(PlatformAdmin admin) {
        if ("LOCKED".equals(admin.getStatus()) || "DISABLED".equals(admin.getStatus())) {
            throw new AuthException(AuthErrorCode.ACCOUNT_LOCKED);
        }
        if (admin.getLockedUntil() != null && admin.getLockedUntil().isAfter(Instant.now())) {
            throw new AuthException(AuthErrorCode.ACCOUNT_LOCKED);
        }
    }

    private void recordFailure(PlatformAdmin admin, String ipAddress) {
        admin.setFailedLoginCount(admin.getFailedLoginCount() + 1);
        int max = properties.password().maxFailures();
        if (admin.getFailedLoginCount() >= max) {
            admin.setLockedUntil(Instant.now().plusSeconds(LOCK_SECONDS));
        }
        admins.save(admin);
    }

    private void resetFailureCount(PlatformAdmin admin) {
        if (admin.getFailedLoginCount() > 0) {
            admin.setFailedLoginCount(0);
            admin.setLockedUntil(null);
            admins.save(admin);
        }
    }
}
