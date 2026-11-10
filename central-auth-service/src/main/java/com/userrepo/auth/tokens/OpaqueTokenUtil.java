package com.userrepo.auth.tokens;

import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates opaque, high-entropy refresh tokens (and authorization codes) and
 * computes their SHA-256 hashes for storage. Refresh tokens are rotated on every
 * use and stored hashed; replay of a rotated token revokes the family (Section 13).
 */
@Component
public class OpaqueTokenUtil {

    private static final int TOKEN_BYTES = 32; // 256 bits
    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();

    private final SecureRandom random = new SecureRandom();

    public String generate() {
        byte[] bytes = new byte[TOKEN_BYTES];
        random.nextBytes(bytes);
        return URL.encodeToString(bytes);
    }

    public String hash(String token) {
        if (token == null) {
            return null;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(token.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            return URL.encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public boolean matches(String token, String storedHash) {
        if (token == null || storedHash == null) {
            return false;
        }
        return constantTimeEquals(hash(token), storedHash);
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
}
