package com.userrepo.auth.tokens;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages ES256 (EC P-256) signing keys (Section 13).
 *
 * <p>Private keys live in a keystore / Vault / cloud KMS in production, never in
 * the repository. For development this service generates an ephemeral keypair
 * on startup and keeps the private key in memory; the public key is persisted in
 * {@code signing_keys_metadata} as a JWK. JWTs carry a {@code kid} in the header.
 *
 * <p>On each startup a new key is generated and previous ACTIVE keys are retired
 * with an overlap window during which their public keys remain in JWKS so
 * already-issued tokens still validate. Multi-instance key generation requires
 * an external key source (documented); in-process generation is dev-only.
 */
@Service
public class SigningKeysService {

    private static final Logger log = LoggerFactory.getLogger(SigningKeysService.class);
    private static final Duration OVERLAP = Duration.ofHours(24);

    private final SigningKeyRepository repository;
    private ECKey activePrivateKey; // includes private 'd'
    private final Map<String, ECKey> verificationKeys = new ConcurrentHashMap<>();

    public SigningKeysService(SigningKeyRepository repository) {
        this.repository = repository;
    }

    @PostConstruct
    @Transactional
    public void init() {
        // Load all usable public keys (active + retired within overlap) for verification.
        List<SigningKey> existing = repository.findByStatusIn(List.of("ACTIVE", "RETIRED"));
        for (SigningKey row : existing) {
            try {
                ECKey pub = ECKey.parse(row.getPublicJwk());
                verificationKeys.put(row.getKid(), pub);
            } catch (Exception e) {
                log.error("Could not parse stored public JWK for kid={}: {}", row.getKid(), e.getMessage());
            }
        }
        // Retire any currently ACTIVE keys; they stay verifiable during the overlap window.
        Instant now = Instant.now();
        for (SigningKey row : existing) {
            if ("ACTIVE".equals(row.getStatus())) {
                row.setStatus("RETIRED");
                row.setRetiredAt(now);
                row.setNotAfter(now.plus(OVERLAP));
                repository.save(row);
            }
        }
        // Generate a new keypair for this run.
        String kid = "es256-" + UUID.randomUUID();
        try {
            ECKey keyPair = new ECKeyGenerator(Curve.P_256)
                    .keyID(kid)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.ES256)
                    .generate();
            this.activePrivateKey = keyPair;

            SigningKey row = new SigningKey();
            row.setKid(kid);
            row.setAlgorithm("ES256");
            row.setPublicJwk(keyPair.toPublicJWK().toJSONString());
            row.setStatus("ACTIVE");
            row.setNotBefore(now);
            repository.save(row);

            verificationKeys.put(kid, keyPair.toPublicJWK());
            log.info("Generated new ES256 signing key with kid={}", kid);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate ES256 signing key", e);
        }
    }

    /** The kid used to sign new tokens. */
    public String activeKid() {
        requireActive();
        return activePrivateKey.getKeyID();
    }

    /** Sign a Nimbus JWSObject in place with the active private key. */
    public void sign(com.nimbusds.jose.JWSObject jwsObject) throws Exception {
        requireActive();
        jwsObject.sign(new ECDSASigner(activePrivateKey));
    }

    /** Public key for verifying tokens with the given kid, or null if unknown. */
    public ECKey verificationKey(String kid) {
        if (kid == null) {
            return null;
        }
        return verificationKeys.get(kid);
    }

    /** All currently verifiable keys as a JWKS (for the /.well-known/jwks.json endpoint). */
    public JWKSet jwkSet() {
        List<JWK> keys = new java.util.ArrayList<>(verificationKeys.values());
        return new JWKSet(keys);
    }

    /** True if a verifier can be built for the given kid. */
    public ECDSAVerifier verifierFor(String kid) throws Exception {
        ECKey pub = verificationKey(kid);
        if (pub == null) {
            return null;
        }
        return new ECDSAVerifier(pub);
    }

    private void requireActive() {
        if (activePrivateKey == null) {
            throw new IllegalStateException("No active signing key; signing keys service not initialised");
        }
    }
}
