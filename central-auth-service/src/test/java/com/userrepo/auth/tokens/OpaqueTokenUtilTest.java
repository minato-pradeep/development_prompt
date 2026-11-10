package com.userrepo.auth.tokens;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class OpaqueTokenUtilTest {

    private final OpaqueTokenUtil util = new OpaqueTokenUtil();

    @Test
    void generate_producesUniqueTokens() {
        String t1 = util.generate();
        String t2 = util.generate();
        assertThat(t1).isNotEqualTo(t2);
    }

    @Test
    void hash_sameInput_sameOutput() {
        String token = util.generate();
        assertThat(util.hash(token)).isEqualTo(util.hash(token));
    }

    @Test
    void matches_correctToken_returnsTrue() {
        String token = util.generate();
        String hash = util.hash(token);
        assertThat(util.matches(token, hash)).isTrue();
    }

    @Test
    void matches_wrongToken_returnsFalse() {
        String token = util.generate();
        String hash = util.hash(token);
        assertThat(util.matches("wrongtoken", hash)).isFalse();
    }

    @Test
    void matches_nullInput_returnsFalse() {
        assertThat(util.matches(null, "somehash")).isFalse();
        assertThat(util.matches("sometoken", null)).isFalse();
    }
}
