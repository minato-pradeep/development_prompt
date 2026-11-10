package com.userrepo.auth.notification;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Service;

/**
 * Development stub for notifications. Logs a safe placeholder — never logs
 * plaintext passwords, OTPs, tokens or recovery codes (Section 18).
 * Replace with a real SMTP / SMS adapter for production.
 */
@Service
@Primary
public class DevNotificationService implements NotificationService {

    private static final Logger log = LoggerFactory.getLogger(DevNotificationService.class);

    @Override
    public void sendPasswordReset(String to, String companyName, String resetToken) {
        // Log only that a reset was requested — never the token value.
        log.info("[DEV-NOTIFICATION] Password reset requested for company='{}' recipient='{}'. " +
                "Token length={} chars. In production this would be delivered via a verified channel.",
                companyName, maskAddress(to), resetToken.length());
    }

    @Override
    public void sendAccountCreated(String to, String username, String companyName) {
        log.info("[DEV-NOTIFICATION] Account created notification for username='{}' company='{}' " +
                "recipient='{}'. Credentials delivered out-of-band.",
                username, companyName, maskAddress(to));
    }

    /** Masks an email/phone so it is safe to log. */
    private static String maskAddress(String addr) {
        if (addr == null || addr.length() < 4) return "***";
        int at = addr.indexOf('@');
        if (at > 0) {
            return addr.substring(0, Math.min(2, at)) + "***" + addr.substring(at);
        }
        return addr.substring(0, 2) + "***";
    }
}
