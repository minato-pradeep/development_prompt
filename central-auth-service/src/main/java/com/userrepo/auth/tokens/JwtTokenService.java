package com.userrepo.auth.tokens;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.userrepo.auth.config.AppProperties;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Issues and validates ES256 access tokens built on Spring Security's Nimbus
 * JOSE support (Section 2, 13). Refresh tokens are opaque (see {@link OpaqueTokenUtil}).
 */
@Component
public class JwtTokenService {

    private final SigningKeysService signingKeys;
    private final AppProperties properties;

    public JwtTokenService(SigningKeysService signingKeys, AppProperties properties) {
        this.signingKeys = signingKeys;
        this.properties = properties;
    }

    public String issueAccessToken(TokenRequest req) {
        Instant now = Instant.now();
        String issuer = issuerFor(req.scope());
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .audience(req.audience())
                .subject(req.subject().toString())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(req.ttlSeconds())))
                .jwtID(UUID.randomUUID().toString())
                .claim(JwtClaims.AUTH_TIME, req.authTime() == null ? now.getEpochSecond() : req.authTime().getEpochSecond())
                .claim(JwtClaims.SID, req.sid().toString())
                .claim(JwtClaims.VER, req.ver())
                .claim(JwtClaims.TYP, JwtClaims.TYP_ACCESS);

        if (req.companyId() != null) {
            claims.claim(JwtClaims.COMPANY_ID, req.companyId().toString());
        }
        if (req.companyCode() != null) {
            claims.claim(JwtClaims.COMPANY_CODE, req.companyCode());
        }
        if (req.roles() != null && !req.roles().isEmpty()) {
            claims.claim(JwtClaims.ROLES, req.roles());
        }
        // Permissions: inline only when the set is small; otherwise a reference
        // plus introspection is used (Section 13).
        if (req.permissions() != null && !req.permissions().isEmpty()) {
            claims.claim(JwtClaims.PERMISSIONS, req.permissions());
        }
        if (req.amr() != null && !req.amr().isEmpty()) {
            claims.claim(JwtClaims.AMR, req.amr());
        }
        if (req.azp() != null) {
            claims.claim(JwtClaims.AZP, req.azp());
        }

        JWSHeader header = new JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.ES256)
                .keyID(signingKeys.activeKid())
                .type(new com.nimbusds.jose.JOSEObjectType(JwtClaims.TYP_ACCESS))
                .build();
        JWSObject jws = new JWSObject(header, new Payload(claims.build().toString()));
        try {
            signingKeys.sign(jws);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign access token", e);
        }
        return jws.serialize();
    }

    /**
     * Validates signature (via kid), expiration, issuer and audience. Returns the
     * decoded claims on success. The caller performs freshness/session checks
     * (ver against current session_version) and introspection for sensitive ops.
     */
    public Optional<DecodedAccessToken> validate(String compactJwt, TokenIssuerScope expectedScope) {
        if (compactJwt == null || compactJwt.isBlank()) {
            return Optional.empty();
        }
        try {
            JWSObject jws = JWSObject.parse(compactJwt);
            String kid = jws.getHeader().getKeyID();
            ECKey pub = signingKeys.verificationKey(kid);
            if (pub == null || !jws.verify(new com.nimbusds.jose.crypto.ECDSAVerifier(pub))) {
                return Optional.empty();
            }
            JWTClaimsSet claims = JWTClaimsSet.parse(jws.getPayload().toString());
            String expectedIssuer = issuerFor(expectedScope);
            if (!expectedIssuer.equals(claims.getIssuer())) {
                return Optional.empty();
            }
            Date exp = claims.getExpirationTime();
            if (exp == null || exp.toInstant().isBefore(Instant.now())) {
                return Optional.empty();
            }
            TokenIssuerScope scope = expectedScope;
            UUID subject = parseUuid(claims.getSubject());
            UUID companyId = claims.getStringClaim(JwtClaims.COMPANY_ID) == null
                    ? null : parseUuid(claims.getStringClaim(JwtClaims.COMPANY_ID));
            List<String> roles = claims.getStringListClaim(JwtClaims.ROLES);
            List<String> permissions = claims.getStringListClaim(JwtClaims.PERMISSIONS);
            List<String> amr = claims.getStringListClaim(JwtClaims.AMR);
            Instant authTime = claims.getLongClaim(JwtClaims.AUTH_TIME) == null
                    ? null : Instant.ofEpochSecond(claims.getLongClaim(JwtClaims.AUTH_TIME));
            UUID sid = claims.getStringClaim(JwtClaims.SID) == null
                    ? null : parseUuid(claims.getStringClaim(JwtClaims.SID));
            Long ver = claims.getLongClaim(JwtClaims.VER);
            String azp = claims.getStringClaim(JwtClaims.AZP);
            String jti = claims.getJWTID();
            String aud = claims.getAudience() == null || claims.getAudience().isEmpty()
                    ? null : claims.getAudience().get(0);
            return Optional.of(new DecodedAccessToken(

                    subject, scope, claims.getIssuer(), aud, companyId,
                    claims.getStringClaim(JwtClaims.COMPANY_CODE), roles, permissions,
                    sid, ver == null ? 0L : ver, authTime, amr, azp, jti, exp.toInstant(), kid));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public String issuerFor(TokenIssuerScope scope) {
        return scope == TokenIssuerScope.PLATFORM
                ? properties.tokens().platformIssuer()
                : properties.tokens().issuer();
    }

    private static UUID parseUuid(String s) {
        if (s == null) return null;
        try {
            return UUID.fromString(s);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
