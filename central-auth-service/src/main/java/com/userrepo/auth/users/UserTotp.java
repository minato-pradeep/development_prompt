package com.userrepo.auth.users;

import jakarta.persistence.*;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/** Encrypted TOTP secret for a company user (Section 6). */
@Entity
@Table(name = "user_totp")
public class UserTotp {

    @Id
    @Column(name = "user_id", updatable = false, nullable = false)
    private UUID userId;

    @Column(name = "secret_cipher", nullable = false)
    private byte[] secretCipher;

    @Column(name = "secret_iv", nullable = false)
    private byte[] secretIv;

    @Column(name = "encryption_kid")
    private String encryptionKid;

    @Column(name = "provisioning_uri")
    private String provisioningUri;

    @Column(name = "last_accepted_step")
    private Long lastAcceptedStep;

    @Column(name = "enrolled_at")
    private Instant enrolledAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public UserTotp() {}

    public UUID getUserId() { return userId; }
    public void setUserId(UUID userId) { this.userId = userId; }
    public byte[] getSecretCipher() { return secretCipher; }
    public void setSecretCipher(byte[] secretCipher) { this.secretCipher = secretCipher; }
    public byte[] getSecretIv() { return secretIv; }
    public void setSecretIv(byte[] secretIv) { this.secretIv = secretIv; }
    public String getEncryptionKid() { return encryptionKid; }
    public void setEncryptionKid(String encryptionKid) { this.encryptionKid = encryptionKid; }
    public String getProvisioningUri() { return provisioningUri; }
    public void setProvisioningUri(String provisioningUri) { this.provisioningUri = provisioningUri; }
    public Long getLastAcceptedStep() { return lastAcceptedStep; }
    public void setLastAcceptedStep(Long lastAcceptedStep) { this.lastAcceptedStep = lastAcceptedStep; }
    public Instant getEnrolledAt() { return enrolledAt; }
    public void setEnrolledAt(Instant enrolledAt) { this.enrolledAt = enrolledAt; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
}
