package com.userrepo.auth.crypto;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Argon2id password hashing (Section 8 / 20) backed by Bouncy Castle.
 *
 * <p>Documented parameters: Argon2id, Argon2 version 1.3, 65536 KiB memory,
 * 3 iterations, parallelism 1, 16-byte random salt, 32-byte hash output. Hashes
 * are stored as a self-describing PHC-style string so they remain verifiable,
 * portable and upgradeable.
 */
@Component
public class Argon2PasswordHasher implements PasswordEncoder {

    static final int SALT_BYTES = 16;
    static final int HASH_BYTES = 32;
    static final int MEMORY_KIB = 65536;
    static final int ITERATIONS = 3;
    static final int PARALLELISM = 1;
    static final int ARGON2_VERSION = Argon2Parameters.ARGON2_VERSION_13;

    private static final String PREFIX = "$argon2id$";
    private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder B64D = Base64.getUrlDecoder();

    private static final Pattern HASH_PATTERN = Pattern.compile(
            "^\\$argon2id\\$v=(\\d+)\\$m=(\\d+),t=(\\d+),p=(\\d+)\\$([A-Za-z0-9_-]+)\\$([A-Za-z0-9_-]+)$");

    private final SecureRandom random = new SecureRandom();

    @Override
    public String encode(CharSequence rawPassword) {
        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        byte[] hash = argon2(passwordBytes(rawPassword), salt, MEMORY_KIB, ITERATIONS, PARALLELISM, HASH_BYTES);
        return encode(salt, hash, MEMORY_KIB, ITERATIONS, PARALLELISM);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        if (encodedPassword == null || !encodedPassword.startsWith(PREFIX)) {
            return false;
        }
        Matcher m = HASH_PATTERN.matcher(encodedPassword);
        if (!m.matches()) {
            return false;
        }
        int memory = Integer.parseInt(m.group(2));
        int iterations = Integer.parseInt(m.group(3));
        int parallelism = Integer.parseInt(m.group(4));
        byte[] salt = B64D.decode(m.group(5));
        byte[] expected = B64D.decode(m.group(6));
        byte[] actual = argon2(passwordBytes(rawPassword), salt, memory, iterations, parallelism, expected.length);
        return constantTimeEquals(actual, expected);
    }

    @Override
    public boolean upgradeEncoding(String encodedPassword) {
        if (encodedPassword == null || !encodedPassword.startsWith(PREFIX)) {
            return true;
        }
        Matcher m = HASH_PATTERN.matcher(encodedPassword);
        if (!m.matches()) {
            return true;
        }
        return Integer.parseInt(m.group(2)) < MEMORY_KIB
                || Integer.parseInt(m.group(3)) < ITERATIONS
                || Integer.parseInt(m.group(4)) < PARALLELISM;
    }

    private static String encode(byte[] salt, byte[] hash, int memory, int iterations, int parallelism) {
        return PREFIX + "v=" + ARGON2_VERSION + "$m=" + memory + ",t=" + iterations + ",p=" + parallelism
                + "$" + B64.encodeToString(salt) + "$" + B64.encodeToString(hash);
    }

    private static byte[] argon2(byte[] password, byte[] salt, int memoryKiB, int iterations, int parallelism,
                                 int hashBytes) {
        Argon2Parameters params = new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(ARGON2_VERSION)
                .withIterations(iterations)
                .withMemoryAsKB(memoryKiB)
                .withParallelism(parallelism)
                .withSalt(salt)
                .build();
        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(params);
        byte[] out = new byte[hashBytes];
        gen.generateBytes(password, out);
        return out;
    }

    private static byte[] passwordBytes(CharSequence raw) {
        return (raw == null ? "" : raw.toString()).getBytes(StandardCharsets.UTF_8);
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }
}
