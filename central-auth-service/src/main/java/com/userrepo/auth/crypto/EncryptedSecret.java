package com.userrepo.auth.crypto;

/**
 * Result of AES-GCM authenticated encryption: the ciphertext (which includes the
 * appended 128-bit GCM authentication tag) and the 96-bit nonce/IV. Both are
 * persisted for at-rest encryption of TOTP secrets (Section 6).
 */
public record EncryptedSecret(byte[] ciphertext, byte[] iv) {
}
