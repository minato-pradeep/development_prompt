package com.userrepo.auth.totp;

import com.userrepo.auth.config.AppProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for TOTP RFC 6238 logic (Section 6).
 * Verifies: code generation, validation within tolerance window, replay detection.
 * No Spring context or DB needed.
 */
class TotpServiceTest {

    private TotpService totpService;

    @BeforeEach
    void setUp() {
        // Build minimal AppProperties with TOTP defaults.
        AppProperties props = new AppProperties(
                new AppProperties.Tokens(
                        "http://localhost:8081", "http://localhost:8081/platform",
                        900, 900, 43200, 1800, 259200, 86400, 1209600, 2592000, 604800, true),
                new AppProperties.Password(12, 5, 5, false, 259200),
                new AppProperties.Totp(30, 6, "HmacSHA1", 1, 10),
                new AppProperties.RateLimit("postgres"),
                new AppProperties.Bootstrap("CENTRAL_AUTH_BOOTSTRAP_SECRET"),
                new AppProperties.Encryption(
                        new AppProperties.Encryption.TotpSecret(
                                "CENTRAL_AUTH_TOTP_MASTER_KEY", "CENTRAL_AUTH_TOTP_MASTER_KID")),
                new AppProperties.Logo(5_242_880L, 1024, 1024, List.of("image/png", "image/jpeg"))
        );
        totpService = new TotpService(props);
    }

    @Test
    void generateSecret_returns20Bytes() {
        byte[] secret = totpService.generateSecret();
        assertThat(secret).hasSize(20);
    }

    @Test
    void validate_currentCode_succeeds() {
        byte[] secret = totpService.generateSecret();
        Instant now = Instant.now();
        String code = totpService.generateCode(secret, now);
        Optional<Long> step = totpService.validate(code, secret, now);
        assertThat(step).isPresent();
    }

    @Test
    void validate_wrongCode_fails() {
        byte[] secret = totpService.generateSecret();
        Optional<Long> step = totpService.validate("000000", secret, Instant.now());
        assertThat(step).isEmpty();
    }

    @Test
    void validate_codeWithinTolerance_succeeds() {
        byte[] secret = totpService.generateSecret();
        // Use a step 1 period in the past.
        Instant past = Instant.now().minusSeconds(30);
        String code = totpService.generateCode(secret, past);
        // Validate against "now" — within +/- 1 step tolerance.
        Optional<Long> step = totpService.validate(code, secret, Instant.now());
        assertThat(step).isPresent();
    }

    @Test
    void isReplay_sameStep_returnsTrue() {
        assertThat(totpService.isReplay(5L, 5L)).isTrue();
    }

    @Test
    void isReplay_olderStep_returnsTrue() {
        assertThat(totpService.isReplay(4L, 5L)).isTrue();
    }

    @Test
    void isReplay_newStep_returnsFalse() {
        assertThat(totpService.isReplay(6L, 5L)).isFalse();
    }

    @Test
    void isReplay_nullLastAccepted_returnsFalse() {
        assertThat(totpService.isReplay(5L, null)).isFalse();
    }

    @Test
    void provisioningUri_containsExpectedFields() {
        byte[] secret = totpService.generateSecret();
        String uri = totpService.provisioningUri("TestApp", "user@test.com", secret);
        assertThat(uri).startsWith("otpauth://totp/");
        assertThat(uri).contains("secret=");
        assertThat(uri).contains("issuer=");
        assertThat(uri).contains("digits=6");
        assertThat(uri).contains("period=30");
    }

    @Test
    void validate_nonNumericCode_fails() {
        byte[] secret = totpService.generateSecret();
        Optional<Long> step = totpService.validate("ABCDEF", secret, Instant.now());
        assertThat(step).isEmpty();
    }

    @Test
    void validate_wrongLengthCode_fails() {
        byte[] secret = totpService.generateSecret();
        Optional<Long> step = totpService.validate("12345", secret, Instant.now());
        assertThat(step).isEmpty();
    }
}
