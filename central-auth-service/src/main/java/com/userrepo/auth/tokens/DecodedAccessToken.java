package com.userrepo.auth.tokens;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Result of validating an access token. */
public record DecodedAccessToken(
        UUID subject,
        TokenIssuerScope scope,
        String issuer,
        String audience,
        UUID companyId,
        String companyCode,
        List<String> roles,
        List<String> permissions,
        UUID sid,
        long ver,
        Instant authTime,
        List<String> amr,
        String azp,
        String jti,
        Instant expiresAt,
        String kid
) {
}
