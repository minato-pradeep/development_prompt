package com.userrepo.auth.platform.dto;

import java.util.List;

/**
 * Returned after successful TOTP activation. Recovery codes are shown ONCE and
 * never again (Section 4, 6).
 */
public record PlatformTotpActivateResponse(
        String accessToken,
        String refreshToken,
        long expiresInSeconds,
        List<String> recoveryCodes  // plaintext, shown once only
) {
}
