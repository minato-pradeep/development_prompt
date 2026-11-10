package com.userrepo.auth.platform;

import com.userrepo.auth.audit.AuditEventType;
import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.config.AppProperties;
import com.userrepo.auth.crypto.Argon2PasswordHasher;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

/**
 * One-time bootstrap of the first Super Admin (Section 4).
 *
 * <p>On first start, if no Super Admin exists, reads the bootstrap secret from
 * {@code CENTRAL_AUTH_BOOTSTRAP_SECRET} (or the configured env var), creates an
 * account with {@code must_change_password = true}, {@code must_enroll_totp = true},
 * and logs the bootstrap event. After any Super Admin exists, the bootstrap path is
 * disabled: the env var is ignored and the endpoint rejects all requests.
 *
 * <p>Bootstrap is audited. The initial username is {@code superadmin}; the password
 * comes from the bootstrap secret (never a hardcoded default).
 */
@Service
public class PlatformBootstrapService {

    private static final Logger log = LoggerFactory.getLogger(PlatformBootstrapService.class);

    private final PlatformAdminRepository adminRepository;
    private final Argon2PasswordHasher hasher;
    private final AppProperties properties;
    private final AuditLogService audit;

    public PlatformBootstrapService(PlatformAdminRepository adminRepository,
                                    Argon2PasswordHasher hasher,
                                    AppProperties properties,
                                    AuditLogService audit) {
        this.adminRepository = adminRepository;
        this.hasher = hasher;
        this.properties = properties;
        this.audit = audit;
    }

    @PostConstruct
    @Transactional
    public void bootstrapIfNeeded() {
        long count = adminRepository.count();
        if (count > 0) {
            log.info("Platform bootstrap: {} Super Admin account(s) already exist; bootstrap skipped.", count);
            return;
        }
        String envVar = properties.bootstrap().secretEnvVar();
        String secret = System.getenv(envVar);
        if (secret == null || secret.isBlank()) {
            log.warn("Platform bootstrap: no Super Admin exists and env var '{}' is not set. "
                    + "The service will start but Super Admin cannot log in until a bootstrap secret "
                    + "is provided and the service is restarted.", envVar);
            return;
        }
        if (secret.length() < 16) {
            log.error("Platform bootstrap: env var '{}' must be at least 16 characters. Bootstrap aborted.", envVar);
            return;
        }

        PlatformAdmin admin = new PlatformAdmin();
        admin.setUsername("superadmin");
        admin.setEmail("superadmin@platform.local");
        admin.setPasswordHash(hasher.encode(secret));
        admin.setMustChangePassword(true);
        admin.setMustEnrollTotp(true);
        admin.setTotpEnabled(false);
        admin.setStatus("ACTIVE");
        admin.setSessionVersion(0L);
        admin.setCreatedAt(Instant.now());
        adminRepository.save(admin);

        audit.builder(AuditEventType.PLATFORM_BOOTSTRAP)
                .actor("SYSTEM", null)
                .target("PLATFORM_ADMIN", admin.getId())
                .result("SUCCESS")
                .meta("username", admin.getUsername())
                .record();

        log.info("Platform bootstrap: Super Admin 'superadmin' created. "
                + "Force password-change and TOTP enrollment required on first login. "
                + "Bootstrap path is now active until TOTP enrollment completes.");
    }

    /** True if bootstrap has already been completed (at least one Super Admin exists). */
    public boolean isBootstrapComplete() {
        return adminRepository.count() > 0;
    }
}
