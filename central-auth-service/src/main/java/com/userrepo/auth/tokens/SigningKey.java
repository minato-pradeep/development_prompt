package com.userrepo.auth.tokens;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

/** Metadata row for a JWT signing key (Section 13). The private key is never stored here. */
@Entity
@Table(name = "signing_keys_metadata")
public class SigningKey {

    @Id
    @Column(name = "kid", updatable = false, nullable = false)
    private String kid;

    @Column(name = "algorithm", nullable = false)
    private String algorithm = "ES256";

    @Column(name = "public_jwk", nullable = false)
    private String publicJwk;

    @Column(name = "status", nullable = false)
    private String status = "ACTIVE"; // ACTIVE | RETIRED | REVOKED

    @Column(name = "not_before", nullable = false)
    private Instant notBefore;

    @Column(name = "not_after")
    private Instant notAfter;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false, nullable = false)
    private Instant createdAt;

    @Column(name = "retired_at")
    private Instant retiredAt;

    public SigningKey() {
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getPublicJwk() {
        return publicJwk;
    }

    public void setPublicJwk(String publicJwk) {
        this.publicJwk = publicJwk;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(Instant notBefore) {
        this.notBefore = notBefore;
    }

    public Instant getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(Instant notAfter) {
        this.notAfter = notAfter;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public Instant getRetiredAt() {
        return retiredAt;
    }

    public void setRetiredAt(Instant retiredAt) {
        this.retiredAt = retiredAt;
    }
}
