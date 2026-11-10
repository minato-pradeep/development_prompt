package com.userrepo.auth.platform.dto;

/**
 * Response to a TOTP setup request. Secret and URI are returned ONLY during
 * initial enrollment and never again (Section 6).
 */
public record PlatformTotpSetupResponse(
        String otpauthUri,      // otpauth:// provisioning URI for QR
        String secretGrouped,   // grouped Base32 for manual entry (Section 30.4)
        String challengeToken   // must be presented to /totp/activate
) {
}
