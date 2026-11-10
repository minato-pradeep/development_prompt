package com.userrepo.auth.platform;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;
import java.util.UUID;

/** Encrypted TOTP secret + replay step for a Super Admin (Section 4, 6). */
@Entity
@Table(name = "platform_admin_totp")
public class PlatformAdminTotp {

    @Id
    @Column(name = "platform_admin_id", updatable = false, nullable = false)
    private UUID platformAdminId;

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

    @UpdateTimestamp
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    public PlatformAdminTotp() {
    }

    public UUID getPlatformAdminId() { return platformAdminId; }
    public void setPlatformAdminId(UUID platformAdminId) { this.platformAdminId = platformAdminId; }
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
    public Instant getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(Instant updatedAt) { this.updatedAt = updatedAt; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
