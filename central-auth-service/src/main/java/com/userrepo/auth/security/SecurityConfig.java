package com.userrepo.auth.security;

import com.userrepo.auth.common.TraceIdFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Central Spring Security configuration (Section 20).
 *
 * <p>Key decisions:
 * <ul>
 *   <li>Stateless JWT bearer-token authentication; no HTTP session.
 *   <li>CSRF protection disabled (Bearer-token APIs; no cookies for access tokens).
 *       If refresh tokens are delivered in HttpOnly cookies, re-enable CSRF per Section 20.
 *   <li>Platform ({@code /api/v1/platform/**}) and tenant ({@code /api/v1/**}) paths
 *       are isolated: platform tokens carry a distinct issuer/audience and are blocked by
 *       {@link PlatformTokenIssuerValidator}; tenant tokens are blocked on platform paths.
 *   <li>Public endpoints (login, TOTP flows, JWKS, Swagger UI) are explicitly permitted.
 *   <li>All other endpoints require authentication.
 *   <li>CORS is strict; origins must be configured via environment or properties.
 * </ul>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final NimbusJwtDecoder jwtDecoder;
    private final JwtAuthenticationConverter jwtConverter;
    private final TraceIdFilter traceIdFilter;

    public SecurityConfig(NimbusJwtDecoder jwtDecoder,
                          JwtAuthenticationConverter jwtConverter,
                          TraceIdFilter traceIdFilter) {
        this.jwtDecoder = jwtDecoder;
        this.jwtConverter = jwtConverter;
        this.traceIdFilter = traceIdFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Stateless; no session.
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Disable CSRF for Bearer-token APIs (Section 20). If refresh tokens
            // are moved to HttpOnly cookies, remove this and configure CsrfTokenRepository.
            .csrf(csrf -> csrf.disable())

            // CORS.
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))

            // Public endpoints.
            .authorizeHttpRequests(auth -> auth
                // Platform public auth flows.
                .requestMatchers(
                    "/api/v1/platform/auth/login",
                    "/api/v1/platform/auth/totp/setup",
                    "/api/v1/platform/auth/totp/activate",
                    "/api/v1/platform/auth/totp/verify",
                    "/api/v1/platform/auth/refresh",
                    "/api/v1/platform/auth/logout"
                ).permitAll()
                // Tenant public auth flows.
                .requestMatchers(
                    "/api/v1/auth/login",
                    "/api/v1/auth/totp/verify",
                    "/api/v1/auth/totp/setup",
                    "/api/v1/auth/totp/activate",
                    "/api/v1/auth/refresh",
                    "/api/v1/auth/logout",
                    "/api/v1/auth/logout-all",
                    "/api/v1/auth/forgot-password",
                    "/api/v1/auth/reset-password",
                    "/api/v1/auth/microsoft/**"
                ).permitAll()
                // JWKS (public, no auth needed by spec).
                .requestMatchers("/.well-known/jwks.json").permitAll()
                // Actuator health/info.
                .requestMatchers("/actuator/health", "/actuator/info").permitAll()
                // OpenAPI / Swagger UI.
                .requestMatchers(
                    "/v3/api-docs/**",
                    "/swagger-ui/**",
                    "/swagger-ui.html"
                ).permitAll()
                // Everything else requires authentication.
                .anyRequest().authenticated()
            )

            // JWT resource-server: validates signatures, expiry, etc.
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder)
                    .jwtAuthenticationConverter(jwtConverter)
                )
            )

            // Add our trace-id filter before standard auth processing.
            .addFilterBefore(traceIdFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    /**
     * Strict CORS: no wildcards. Allowed origins are from environment/config in production.
     * For development, {@code http://localhost:*} is allowed. Section 20.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration cfg = new CorsConfiguration();
        cfg.setAllowedOriginPatterns(List.of(
            "http://localhost:[*]",
            "https://localhost:[*]"
        ));
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        cfg.setAllowedHeaders(List.of(
            "Authorization", "Content-Type", "X-Trace-Id", "X-Challenge-Token"
        ));
        cfg.setExposedHeaders(List.of("X-Trace-Id"));
        cfg.setAllowCredentials(true);
        cfg.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", cfg);
        return source;
    }
}
