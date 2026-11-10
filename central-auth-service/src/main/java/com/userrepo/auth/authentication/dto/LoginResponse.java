package com.userrepo.auth.authentication.dto;

/**
 * Login response. If onboarding or TOTP is required, accessToken/refreshToken
 * are null and challenge carries a short-lived token.
 */
public record LoginResponse(
        String accessToken,
        String refreshToken,
        long   expiresInSeconds,
        String challenge,
        String challengeType   // ONBOARDING | TOTP_VERIFY | null
) {}
