package com.userrepo.auth.tokens;

import com.nimbusds.jose.jwk.JWKSet;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves the JWKS (JSON Web Key Set) at {@code /.well-known/jwks.json} (Section 16).
 * This endpoint is public. Other microservices fetch this to verify ES256 JWTs without
 * calling this service on every request (Section 14).
 */
@RestController
@Tag(name = "Token & Identity", description = "JWKS, introspection, revocation")
public class JwksController {

    private final SigningKeysService signingKeysService;

    public JwksController(SigningKeysService signingKeysService) {
        this.signingKeysService = signingKeysService;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    @Operation(summary = "JSON Web Key Set (public)")
    public ResponseEntity<String> jwks() {
        JWKSet jwkSet = signingKeysService.jwkSet();
        // toPublicJWKSet() strips any private key material (safety guard).
        return ResponseEntity.ok(jwkSet.toPublicJWKSet().toString());
    }
}
