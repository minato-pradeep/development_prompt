package com.userrepo.auth.totp;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class Base32Test {

    @Test
    void roundTrip_encodeDeocde() {
        byte[] data = "Hello, World!".getBytes();
        String encoded = Base32.encode(data);
        assertThat(Base32.decode(encoded)).isEqualTo(data);
    }

    @Test
    void encode_emptyArray_returnsEmpty() {
        assertThat(Base32.encode(new byte[0])).isEmpty();
    }

    @Test
    void decode_invalidChar_throwsException() {
        assertThatThrownBy(() -> Base32.decode("ABC!DEF"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void decode_isCaseInsensitive() {
        byte[] data = {1, 2, 3, 4, 5};
        String upper = Base32.encode(data);
        assertThat(Base32.decode(upper.toLowerCase())).isEqualTo(Base32.decode(upper));
    }
}
