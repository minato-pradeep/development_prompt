package com.userrepo.auth.tokens;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Inputs needed to issue an access token (Section 13, 30.6).
 */
public record TokenRequest(
        UUID subject,
        TokenIssuerScope scope,
        String audience,
        UUID companyId,
        String companyCode,
        List<String> roles,
        List<String> permissions, // null/empty -> a reference is used instead of inlining claims
        UUID sid,
        long ver,
        Instant authTime,
        List<String> amr,
        String azp,       // client_id (authorized party); null if not client-scoped
        long ttlSeconds
) {
}
