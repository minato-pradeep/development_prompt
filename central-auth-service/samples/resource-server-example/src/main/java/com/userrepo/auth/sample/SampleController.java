package com.userrepo.auth.sample;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Sample protected endpoint demonstrating JWT claim extraction.
 * Requires a valid JWT from central-auth-service (ES256, correct issuer and audience).
 */
@RestController
@RequestMapping("/api/sample")
public class SampleController {

    @GetMapping("/resource")
    public ResponseEntity<Map<String, Object>> protectedResource(
            @AuthenticationPrincipal Jwt jwt) {
        // Claims are injected by Spring Security after signature + issuer + exp validation.
        return ResponseEntity.ok(Map.of(
                "sub",        jwt.getSubject(),
                "company_id", jwt.getClaimAsString("company_id"),
                "roles",      jwt.getClaimAsStringList("roles"),
                "expires_at", jwt.getExpiresAt()
        ));
    }
}
