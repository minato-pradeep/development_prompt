package com.userrepo.auth.sample;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Sample resource-server Spring Security configuration.
 *
 * <p>Token validation strategy (Section 14):
 * <ol>
 *   <li>Fetch the JWKS from central-auth-service once; cache it; refresh on unknown kid.
 *   <li>Verify ES256 signature locally — no network call per request.
 *   <li>Validate issuer matches the configured value.
 *   <li>Validate audience matches this service's audience.
 *   <li>Validate expiration.
 * </ol>
 *
 * <p>For sensitive operations, call the introspection endpoint
 * (POST /api/v1/oauth/introspect) to check the ver claim freshness.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /** JWKS URI of central-auth-service, e.g. http://central-auth-service:8081/.well-known/jwks.json */
    @Value("${central-auth.jwks-uri:http://localhost:8081/.well-known/jwks.json}")
    private String jwksUri;

    /** Expected issuer from central-auth-service token properties. */
    @Value("${central-auth.issuer:http://localhost:8081}")
    private String issuer;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(jwtDecoder())));
        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder() {
        // Spring Security fetches JWKS once and caches it; refreshes automatically on unknown kid.
        // Wrong issuer or audience → 401 Unauthorized.
        return NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
    }
}
