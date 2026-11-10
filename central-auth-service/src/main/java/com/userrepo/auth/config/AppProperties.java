package com.userrepo.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;

import java.util.List;

/**
 * Strongly-typed view of the {@code app.*} configuration namespace in
 * {@code application.yml}. Bound via constructor binding (Spring Boot 4).
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(
        @NestedConfigurationProperty Tokens tokens,
        @NestedConfigurationProperty Password password,
        @NestedConfigurationProperty Totp totp,
        @NestedConfigurationProperty RateLimit rateLimit,
        @NestedConfigurationProperty Bootstrap bootstrap,
        @NestedConfigurationProperty Encryption encryption,
        @NestedConfigurationProperty Logo logo
) {

    /** Token issuance + refresh lifetimes (Section 13, 30.6). */
    public record Tokens(
            String issuer,
            String platformIssuer,
            long accessTokenTtlSeconds,
            long platformAccessTokenTtlSeconds,
            long refreshWebAbsoluteSeconds,
            long refreshWebIdleSeconds,
            long refreshDesktopAbsoluteSeconds,
            long refreshDesktopIdleSeconds,
            long refreshMobileAbsoluteSeconds,
            long refreshMobileIdleSeconds,
            long adminRefreshDesktopMobileAbsoluteSeconds,
            boolean refreshRotation
    ) {
        public long accessTokenTtlSeconds() {
            return accessTokenTtlSeconds > 0 ? accessTokenTtlSeconds : 900L;
        }
    }

    /** Password policy defaults (Section 8). */
    public record Password(
            int minLength,
            int historyCount,
            int maxFailures,
            boolean breachedPasswordCheck,
            long tempPasswordTtlSeconds
    ) {
        public int minLength() {
            return minLength > 0 ? minLength : 12;
        }
    }

    /** TOTP (Section 6): RFC 6238, HMAC-SHA1, 6 digits, 30s, +/-1 step. */
    public record Totp(
            int periodSeconds,
            int digits,
            String algorithm,
            int toleranceSteps,
            int recoveryCodeCount
    ) {
        public int periodSeconds() {
            return periodSeconds > 0 ? periodSeconds : 30;
        }

        public int digits() {
            return digits > 0 ? digits : 6;
        }

        public int toleranceSteps() {
            return toleranceSteps >= 0 ? toleranceSteps : 1;
        }

        public int recoveryCodeCount() {
            return recoveryCodeCount > 0 ? recoveryCodeCount : 10;
        }
    }

    /** Rate limiting / lockout storage (Section 20). PostgreSQL for multi-instance consistency. */
    public record RateLimit(String store) {
    }

    /** Bootstrap of the first Super Admin (Section 4). */
    public record Bootstrap(String secretEnvVar) {
        public String secretEnvVar() {
            return secretEnvVar != null && !secretEnvVar.isBlank() ? secretEnvVar : "CENTRAL_AUTH_BOOTSTRAP_SECRET";
        }
    }

    /** Master encryption key for TOTP secrets at rest (Section 6). */
    public record Encryption(@NestedConfigurationProperty TotpSecret totpSecret) {
        public record TotpSecret(String masterKeyEnvVar, String kidEnvVar) {
            public String masterKeyEnvVar() {
                return masterKeyEnvVar != null && !masterKeyEnvVar.isBlank()
                        ? masterKeyEnvVar : "CENTRAL_AUTH_TOTP_MASTER_KEY";
            }

            public String kidEnvVar() {
                return kidEnvVar != null && !kidEnvVar.isBlank() ? kidEnvVar : "CENTRAL_AUTH_TOTP_MASTER_KID";
            }
        }
    }

    /** Logo upload limits (Section 8). */
    public record Logo(long maxSizeBytes, int maxWidthPx, int maxHeightPx, List<String> allowedContentTypes) {
        public long maxSizeBytes() {
            return maxSizeBytes > 0 ? maxSizeBytes : 5_242_880L;
        }

        public int maxWidthPx() {
            return maxWidthPx > 0 ? maxWidthPx : 1024;
        }

        public int maxHeightPx() {
            return maxHeightPx > 0 ? maxHeightPx : 1024;
        }
    }
}
