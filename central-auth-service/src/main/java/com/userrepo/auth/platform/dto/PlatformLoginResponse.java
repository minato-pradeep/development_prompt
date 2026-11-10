package com.userrepo.auth.platform.dto;

/**
 * Returned after password-only verification. If TOTP is still required the
 * {@code challenge} field carries the short-lived onboarding/TOTP challenge
 * token; {@code accessToken} is absent until TOTP succeeds.
 */
public record PlatformLoginResponse(
        String accessToken,         // null if TOTP not yet verified
        String refreshToken,        // null if TOTP not yet verified
        long expiresInSeconds,
        String challenge,           // non-null when TOTP or onboarding is required
        String challengeType        // ONBOARDING | TOTP_VERIFY
) {
}
