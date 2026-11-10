package com.userrepo.auth.notification;

/**
 * Notification abstraction for recovery channels (Section 18). A dev stub logs
 * a placeholder message; a real implementation sends via SMTP or SMS provider.
 * Passwords, OTPs, recovery codes and tokens are NEVER passed to this interface.
 */
public interface NotificationService {

    /**
     * Sends a password-reset link to the user's verified channel.
     *
     * @param to          recipient address (email or phone)
     * @param companyName human-readable company name
     * @param resetToken  opaque, single-use reset token (NOT a plaintext password)
     */
    void sendPasswordReset(String to, String companyName, String resetToken);

    /**
     * Sends a temporary account invitation to the user's verified channel.
     * The plaintext temporary password is NEVER passed here — only a notification
     * that an account has been created. Credentials are delivered out-of-band.
     *
     * @param to         recipient address
     * @param username   the username that was created
     * @param companyName human-readable company name
     */
    void sendAccountCreated(String to, String username, String companyName);
}
