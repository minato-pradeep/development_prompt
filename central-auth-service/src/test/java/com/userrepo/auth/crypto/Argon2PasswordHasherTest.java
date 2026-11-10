package com.userrepo.auth.crypto;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Argon2id password hashing (Section 8/20).
 * No Spring context or database needed.
 */
class Argon2PasswordHasherTest {

    private final Argon2PasswordHasher hasher = new Argon2PasswordHasher();

    @Test
    void encode_producesArgon2idHash() {
        String hash = hasher.encode("SecurePassword123!");
        assertThat(hash).startsWith("$argon2id$");
    }

    @Test
    void matches_correctPassword_returnsTrue() {
        String hash = hasher.encode("SecurePassword123!");
        assertThat(hasher.matches("SecurePassword123!", hash)).isTrue();
    }

    @Test
    void matches_wrongPassword_returnsFalse() {
        String hash = hasher.encode("SecurePassword123!");
        assertThat(hasher.matches("WrongPassword!", hash)).isFalse();
    }

    @Test
    void encode_differentSaltsEachTime() {
        String h1 = hasher.encode("SamePassword");
        String h2 = hasher.encode("SamePassword");
        assertThat(h1).isNotEqualTo(h2);
        // But both match the original password.
        assertThat(hasher.matches("SamePassword", h1)).isTrue();
        assertThat(hasher.matches("SamePassword", h2)).isTrue();
    }

    @Test
    void upgradeEncoding_falseForCurrentParams() {
        String hash = hasher.encode("password");
        assertThat(hasher.upgradeEncoding(hash)).isFalse();
    }

    @Test
    void matches_nullPassword_returnsFalse() {
        String hash = hasher.encode("password");
        assertThat(hasher.matches(null, hash)).isFalse();
    }
}
