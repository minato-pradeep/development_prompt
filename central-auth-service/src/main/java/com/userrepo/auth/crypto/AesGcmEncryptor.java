package com.userrepo.auth.crypto;

import com.userrepo.auth.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Authenticated encryption (AES-256-GCM) for secrets at rest, used for TOTP
 * secrets (Section 6). The master key comes from a secret manager / env var
 * (never the repository). Key identifier and rotation are supported via the
 * encryption kid recorded alongside the ciphertext.
 *
 * <p>Development fallback: if no master key is configured, a random ephemeral
 * key is generated and a loud warning is logged. This is explicitly NOT for
 * production; existing encrypted secrets cannot be decrypted after a restart.
 */
@Component
public class AesGcmEncryptor {

    private static final Logger log = LoggerFactory.getLogger(AesGcmEncryptor.class);

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_BYTES = 12;      // 96-bit IV recommended for GCM
    private static final int TAG_BITS = 128;    // default GCM tag length

    private final Key masterKey;
    private final String kid;
    private final SecureRandom random = new SecureRandom();

    public AesGcmEncryptor(AppProperties properties) {
        AppProperties.Encryption.TotpSecret cfg = properties.encryption() == null
                ? null : properties.encryption().totpSecret();
        String keyEnvVar = cfg != null ? cfg.masterKeyEnvVar() : "CENTRAL_AUTH_TOTP_MASTER_KEY";
        String kidEnvVar = cfg != null ? cfg.kidEnvVar() : "CENTRAL_AUTH_TOTP_MASTER_KID";
        String keyB64 = System.getenv(keyEnvVar);
        if (keyB64 == null || keyB64.isBlank()) {
            byte[] ephemeral = new byte[32];
            random.nextBytes(ephemeral);
            this.masterKey = new SecretKeySpec(ephemeral, "AES");
            this.kid = System.getenv(kidEnvVar);
            log.warn("No TOTP master key found in env var '{}'. Using a random EPHEMERAL key (development only). "
                    + "Encrypted TOTP secrets will be undecryptable after a restart. Set '{}' (base64 32-byte key) "
                    + "for production.", keyEnvVar, keyEnvVar);
        } else {
            byte[] keyBytes = Base64.getDecoder().decode(keyB64.trim());
            if (keyBytes.length != 16 && keyBytes.length != 24 && keyBytes.length != 32) {
                throw new IllegalStateException("Master key for env var '" + keyEnvVar
                        + "' must decode to 16/24/32 bytes (AES-128/192/256), got " + keyBytes.length);
            }
            this.masterKey = new SecretKeySpec(keyBytes, "AES");
            this.kid = System.getenv(kidEnvVar);
        }
    }

    public EncryptedSecret encrypt(byte[] plaintext) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext);
            return new EncryptedSecret(ciphertext, iv);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM encryption failed", e);
        }
    }

    public byte[] decrypt(byte[] ciphertext, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, masterKey, new GCMParameterSpec(TAG_BITS, iv));
            return cipher.doFinal(ciphertext);
        } catch (Exception e) {
            throw new IllegalStateException("AES-GCM decryption failed (wrong key or tampered ciphertext)", e);
        }
    }

    /** Key identifier in use, if configured via the env var. May be null in dev. */
    public String currentKid() {
        return kid;
    }
}
