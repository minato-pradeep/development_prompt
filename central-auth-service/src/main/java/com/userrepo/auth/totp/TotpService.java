package com.userrepo.auth.totp;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import com.userrepo.auth.config.AppProperties;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * RFC 6238 TOTP: HMAC-SHA1, 6 digits, 30-second period, configurable clock
 * tolerance (default +/- 1 step). Unique secret per account. The secret is a
 * random 160-bit key (RFC 4226 recommendation).
 *
 * <p>Uses java-otp 1.0.0 API: {@link TimeBasedOneTimePasswordGenerator}.
 * Replay prevention (last accepted time step, atomic update under row lock) is
 * enforced by the DB layer (Section 6) so concurrent reuse of the same code is
 * rejected.
 */
@Component
public class TotpService {

    private static final int SECRET_BYTES = 20; // 160 bits

    private final int periodSeconds;
    private final int digits;
    private final int toleranceSteps;
    private final TimeBasedOneTimePasswordGenerator generator;
    private final SecureRandom random = new SecureRandom();

    public TotpService(AppProperties properties) {
        AppProperties.Totp cfg = properties.totp();
        this.periodSeconds = cfg.periodSeconds();
        this.digits = cfg.digits();
        this.toleranceSteps = cfg.toleranceSteps();
        try {
            this.generator = new TimeBasedOneTimePasswordGenerator(
                    Duration.ofSeconds(periodSeconds),
                    digits,
                    TimeBasedOneTimePasswordGenerator.TOTP_ALGORITHM_HMAC_SHA1);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("HMAC-SHA1 unavailable", e);
        }
    }

    /** Generates a fresh 160-bit TOTP secret. */
    public byte[] generateSecret() {
        byte[] secret = new byte[SECRET_BYTES];
        random.nextBytes(secret);
        return secret;
    }

    /** Builds the otpauth:// provisioning URI for QR rendering (Section 6). */
    public String provisioningUri(String issuer, String accountName, byte[] secret) {
        String issuerEnc = urlEncode(issuer);
        String label = urlEncode(issuer + ":" + accountName);
        return "otpauth://totp/" + label
                + "?secret=" + Base32.encode(secret)
                + "&issuer=" + issuerEnc
                + "&algorithm=SHA1"
                + "&digits=" + digits
                + "&period=" + periodSeconds;
    }

    /** The Base32 secret formatted in groups of 4 for manual entry (Section 30.4). */
    public String groupedSecret(byte[] secret) {
        String b32 = Base32.encode(secret);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < b32.length(); i++) {
            if (i > 0 && i % 4 == 0) {
                sb.append(' ');
            }
            sb.append(b32.charAt(i));
        }
        return sb.toString();
    }

    public String generateCode(byte[] secret, Instant instant) {
        try {
            return generator.generateOneTimePasswordString(secretKey(secret), instant);
        } catch (Exception e) {
            throw new IllegalStateException("TOTP generation failed", e);
        }
    }

    /**
     * Validates the code within the tolerance window. On success returns the
     * accepted time step number (seconds since epoch / period). The caller must
     * persist this as the last accepted step atomically and reject any later code
     * whose step is &lt;= that value (replay prevention).
     */
    public Optional<Long> validate(String code, byte[] secret, Instant now) {
        if (code == null || code.length() != digits || !isNumeric(code)) {
            return Optional.empty();
        }
        long baseStep = now.getEpochSecond() / periodSeconds;
        SecretKey key = secretKey(secret);
        for (int offset = -toleranceSteps; offset <= toleranceSteps; offset++) {
            long step = baseStep + offset;
            Instant instant = Instant.ofEpochSecond(step * (long) periodSeconds);
            try {
                String expected = generator.generateOneTimePasswordString(key, instant);
                if (constantTimeEquals(code, expected)) {
                    return Optional.of(step);
                }
            } catch (Exception e) {
                // Continue to next step.
            }
        }
        return Optional.empty();
    }

    /** True if the given step has already been used (strict replay prevention). */
    public boolean isReplay(long step, Long lastAcceptedStep) {
        return lastAcceptedStep != null && step <= lastAcceptedStep;
    }

    public int periodSeconds() {
        return periodSeconds;
    }

    public int digits() {
        return digits;
    }

    private static SecretKey secretKey(byte[] secret) {
        return new SecretKeySpec(secret, "HmacSHA1");
    }

    private static boolean isNumeric(String s) {
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null || a.length() != b.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= a.charAt(i) ^ b.charAt(i);
        }
        return diff == 0;
    }

    private static String urlEncode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
