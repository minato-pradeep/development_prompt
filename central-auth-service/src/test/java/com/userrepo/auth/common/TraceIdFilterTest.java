package com.userrepo.auth.common;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/** Unit tests for the TraceIdFilter sanitizer. */
class TraceIdFilterTest {

    private final TraceIdFilter filter = new TraceIdFilter();

    private String sanitize(String input) throws Exception {
        Method m = TraceIdFilter.class.getDeclaredMethod("sanitize", String.class);
        m.setAccessible(true);
        return (String) m.invoke(filter, input);
    }

    @Test
    void sanitize_validUuid_passesThrough() throws Exception {
        String id = "550e8400-e29b-41d4-a716-446655440000";
        assertThat(sanitize(id)).isEqualTo(id);
    }

    @Test
    void sanitize_null_returnsNull() throws Exception {
        assertThat(sanitize(null)).isNull();
    }

    @Test
    void sanitize_specialChars_returnsNull() throws Exception {
        assertThat(sanitize("<script>alert(1)</script>")).isNull();
    }

    @Test
    void sanitize_tooLong_returnsNull() throws Exception {
        assertThat(sanitize("a".repeat(129))).isNull();
    }

    @Test
    void sanitize_empty_returnsNull() throws Exception {
        assertThat(sanitize("")).isNull();
    }
}
