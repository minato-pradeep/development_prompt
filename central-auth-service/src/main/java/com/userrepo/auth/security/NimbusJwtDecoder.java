package com.userrepo.auth.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.userrepo.auth.tokens.SigningKeysService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

/**
 * Spring Security {@link JwtDecoder} backed by our in-process Nimbus JWK set.
 * Used by Spring Security's resource-server filter to validate inbound JWTs.
 * Builds a fresh decoder per call so key rotation (new keys added to the JWK set
 * after startup) is reflected immediately.
 */
@Component
public class NimbusJwtDecoder implements JwtDecoder {

    private final SigningKeysService signingKeysService;

    public NimbusJwtDecoder(SigningKeysService signingKeysService) {
        this.signingKeysService = signingKeysService;
    }

    @Override
    public Jwt decode(String token) throws JwtException {
        // Build a DefaultJWTProcessor with our local JWK set, then wrap it in
        // Spring Security's NimbusJwtDecoder using the withJwtProcessor builder.
        DefaultJWTProcessor<SecurityContext> proc = new DefaultJWTProcessor<>();
        proc.setJWSKeySelector(new JWSVerificationKeySelector<>(
                JWSAlgorithm.ES256,
                new ImmutableJWKSet<>(signingKeysService.jwkSet())));

        org.springframework.security.oauth2.jwt.NimbusJwtDecoder decoder =
                org.springframework.security.oauth2.jwt.NimbusJwtDecoder
                        .withJwkSource(new ImmutableJWKSet<>(signingKeysService.jwkSet()))
                        .build();
        return decoder.decode(token);
    }
}
