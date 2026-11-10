package com.userrepo.auth.users;

import com.userrepo.auth.audit.AuditEventType;
import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.company.CompanyAuthSettings;
import com.userrepo.auth.company.CompanyAuthSettingsRepository;
import com.userrepo.auth.company.CompanyRepository;
import com.userrepo.auth.company.CompanySettingsRepository;
import com.userrepo.auth.config.AppProperties;
import com.userrepo.auth.crypto.Argon2PasswordHasher;
import com.userrepo.auth.notification.NotificationService;
import com.userrepo.auth.permissions.PermissionRepository;
import com.userrepo.auth.roles.*;
import com.userrepo.auth.users.dto.*;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Company Admin user management (Section 7, 10, 11).
 * Enforces: username uniqueness within company, privilege-escalation protection,
 * email uniqueness per company policy, cross-company isolation.
 */
@Service
public class UserManagementService {

    private final UserRepository           users;
    private final UserSessionRepository    sessions;
    private final RefreshTokenRepository   refreshTokens;
    private final PasswordHistoryRepository pwHistory;
    private final UserRoleRepository       userRoles;
    private final RoleRepository           roles;
    private final RolePermissionRepository rolePerms;
    private final PermissionRepository     permissions;
    private final CompanyRepository        companies;
    private final CompanySettingsRepository companySettings;
    private final CompanyAuthSettingsRepository authSettings;
    private final Argon2PasswordHasher     hasher;
    private final NotificationService      notifications;
    private final AuditLogService          audit;
    private final AppProperties            properties;
    private final SecureRandom             random = new SecureRandom();

    public UserManagementService(UserRepository users,
                                 UserSessionRepository sessions,
                                 RefreshTokenRepository refreshTokens,
                                 PasswordHistoryRepository pwHistory,
                                 UserRoleRepository userRoles,
                                 RoleRepository roles,
                                 RolePermissionRepository rolePerms,
                                 PermissionRepository permissions,
                                 CompanyRepository companies,
                                 CompanySettingsRepository companySettings,
                                 CompanyAuthSettingsRepository authSettings,
                                 Argon2PasswordHasher hasher,
                                 NotificationService notifications,
                                 AuditLogService audit,
                                 AppProperties properties) {
        this.users           = users;
        this.sessions        = sessions;
        this.refreshTokens   = refreshTokens;
        this.pwHistory       = pwHistory;
        this.userRoles       = userRoles;
        this.roles           = roles;
        this.rolePerms       = rolePerms;
        this.permissions     = permissions;
        this.companies       = companies;
        this.companySettings = companySettings;
        this.authSettings    = authSettings;
        this.hasher          = hasher;
        this.notifications   = notifications;
        this.audit           = audit;
        this.properties      = properties;
    }

    // -------------------------------------------------------------------------
    // Create user
    // -------------------------------------------------------------------------
    @Transactional
    public User createUser(UUID companyId, CreateUserRequest req, UUID actorId) {
        // Cross-company guard: actorId must belong to companyId (enforced by caller/security layer).
        String normalized = req.username().toLowerCase();
        if (users.existsByCompanyIdAndNormalizedUsername(companyId, normalized)) {
            throw new AuthException(AuthErrorCode.USERNAME_TAKEN,
                    "Username already exists in this company");
        }

        // Email uniqueness per company policy (Section 8).
        companySettings.findByCompanyId(companyId).ifPresent(cs -> {
            if (cs.isEmailUniquePerCompany() && req.email() != null) {
                users.findByCompanyIdAndEmailIgnoreCase(companyId, req.email()).ifPresent(u -> {
                    throw new AuthException(AuthErrorCode.CONFLICT,
                            "Email already registered in this company");
                });
            }
        });

        boolean generated = (req.temporaryPassword() == null || req.temporaryPassword().isBlank());
        String plain = generated ? generatePassword() : req.temporaryPassword();

        CompanyAuthSettings cas = authSettings.findByCompanyId(companyId)
                .orElse(new CompanyAuthSettings());

        User user = new User();
        user.setCompanyId(companyId);
        user.setUsername(req.username());
        user.setNormalizedUsername(normalized);
        user.setEmail(req.email());
        user.setMobileNumber(req.mobileNumber());
        user.setFirstName(req.firstName());
        user.setLastName(req.lastName());
        user.setEmployeeCode(req.employeeCode());
        user.setDepartment(req.department());
        user.setDesignation(req.designation());
        user.setStatus("ACTIVE");
        user.setPasswordHash(hasher.encode(plain));
        user.setMustChangePassword(true);
        user.setMustEnrollTotp("PASSWORD_TOTP".equals(cas.getLoginMethod()));
        user.setCreatedBy(actorId);
        user.setCreatedAt(Instant.now());
        users.save(user);

        if (req.email() != null) {
            notifications.sendAccountCreated(req.email(), req.username(),
                    companyId.toString());
        }

        audit.builder(AuditEventType.USER_CREATED)
                .actor("USER", actorId).company(companyId)
                .target("USER", user.getId()).result("SUCCESS").record();

        return user;
    }

    // -------------------------------------------------------------------------
    // Read
    // -------------------------------------------------------------------------
    @Transactional(readOnly = true)
    public Page<User> listUsers(UUID companyId, Pageable pageable) {
        return users.findAll(
                (root, q, cb) -> cb.equal(root.get("companyId"), companyId), pageable);
    }

    @Transactional(readOnly = true)
    public User getUser(UUID companyId, UUID userId) {
        User u = users.findById(userId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND));
        assertSameCompany(u.getCompanyId(), companyId);
        return u;
    }

    // -------------------------------------------------------------------------
    // Update
    // -------------------------------------------------------------------------
    @Transactional
    public User updateUser(UUID companyId, UUID userId, UpdateUserRequest req, UUID actorId) {
        User u = getUser(companyId, userId);
        if (req.email() != null)       u.setEmail(req.email());
        if (req.mobileNumber() != null) u.setMobileNumber(req.mobileNumber());
        if (req.firstName() != null)   u.setFirstName(req.firstName());
        if (req.lastName() != null)    u.setLastName(req.lastName());
        if (req.employeeCode() != null) u.setEmployeeCode(req.employeeCode());
        if (req.department() != null)  u.setDepartment(req.department());
        if (req.designation() != null) u.setDesignation(req.designation());
        users.save(u);
        audit.builder(AuditEventType.USER_UPDATED)
                .actor("USER", actorId).company(companyId).target("USER", userId).result("SUCCESS").record();
        return u;
    }

    // -------------------------------------------------------------------------
    // Status change
    // -------------------------------------------------------------------------
    @Transactional
    public void updateStatus(UUID companyId, UUID userId, String status, UUID actorId) {
        User u = getUser(companyId, userId);
        u.setStatus(status);
        u.setSessionVersion(u.getSessionVersion() + 1);
        users.save(u);
        // Revoke sessions immediately on deactivation (Section 14).
        if (!"ACTIVE".equals(status)) {
            Instant now = Instant.now();
            refreshTokens.revokeAllByUser(userId, now);
            sessions.revokeAllByUserId(userId, now);
        }
        audit.builder(AuditEventType.USER_DEACTIVATED)
                .actor("USER", actorId).company(companyId).target("USER", userId)
                .result("SUCCESS").meta("status", status).record();
    }

    // -------------------------------------------------------------------------
    // Unlock
    // -------------------------------------------------------------------------
    @Transactional
    public void unlockUser(UUID companyId, UUID userId, UUID actorId) {
        User u = getUser(companyId, userId);
        u.setLockedUntil(null);
        u.setFailedLoginCount(0);
        if ("LOCKED".equals(u.getStatus())) u.setStatus("ACTIVE");
        users.save(u);
        audit.builder(AuditEventType.USER_UNLOCKED)
                .actor("USER", actorId).company(companyId).target("USER", userId).result("SUCCESS").record();
    }

    // -------------------------------------------------------------------------
    // Admin reset password (Section 18)
    // -------------------------------------------------------------------------
    @Transactional
    public String adminResetPassword(UUID companyId, UUID userId,
                                     AdminResetPasswordRequest req, UUID actorId) {
        User u = getUser(companyId, userId);
        // Company Admin cannot reset their own password via this admin API (Section 7).
        if (u.getId().equals(actorId)) {
            throw new AuthException(AuthErrorCode.FORBIDDEN,
                    "Cannot reset your own password via the admin API");
        }
        boolean generated = (req.temporaryPassword() == null || req.temporaryPassword().isBlank());
        String plain = generated ? generatePassword() : req.temporaryPassword();

        pwHistory.save(buildHistory(userId, u.getPasswordHash()));
        u.setPasswordHash(hasher.encode(plain));
        u.setMustChangePassword(true);
        u.setSessionVersion(u.getSessionVersion() + 1);
        users.save(u);

        Instant now = Instant.now();
        refreshTokens.revokeAllByUser(userId, now);
        sessions.revokeAllByUserId(userId, now);

        audit.builder(AuditEventType.USER_PASSWORD_RESET)
                .actor("USER", actorId).company(companyId).target("USER", userId).result("SUCCESS").record();

        return generated ? plain : null;
    }

    // -------------------------------------------------------------------------
    // Role assignment (Section 11 privilege-escalation rule)
    // -------------------------------------------------------------------------
    @Transactional
    public void assignRoles(UUID companyId, UUID targetUserId,
                            List<UUID> roleIds, UUID actorId) {
        User target = getUser(companyId, targetUserId);

        // Privilege-escalation: actor cannot assign roles whose permissions are a superset
        // of their own, and cannot assign roles to themselves.
        if (targetUserId.equals(actorId)) {
            throw new AuthException(AuthErrorCode.PRIVILEGE_ESCALATION_DENIED,
                    "Cannot assign roles to yourself");
        }

        Set<UUID> actorPerms = getEffectivePermissionIds(actorId);
        for (UUID roleId : roleIds) {
            Role role = roles.findById(roleId)
                    .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND, "Role not found"));
            assertSameCompany(role.getCompanyId(), companyId);
            Set<UUID> rolePermIds = rolePerms.findByRoleId(roleId).stream()
                    .map(rp -> rp.getPermissionId()).collect(Collectors.toSet());
            if (!actorPerms.containsAll(rolePermIds)) {
                throw new AuthException(AuthErrorCode.PRIVILEGE_ESCALATION_DENIED,
                        "Cannot assign a role with permissions you do not hold");
            }
        }

        userRoles.deleteAllByUserId(targetUserId);
        for (UUID roleId : roleIds) {
            userRoles.save(new UserRoleEntity(targetUserId, roleId));
        }
        target.setSessionVersion(target.getSessionVersion() + 1);
        users.save(target);

        audit.builder(AuditEventType.ROLE_ASSIGNED)
                .actor("USER", actorId).company(companyId).target("USER", targetUserId)
                .result("SUCCESS").meta("roles", roleIds.toString()).record();
    }

    // -------------------------------------------------------------------------
    // Effective permissions for a user (used for privilege-escalation check)
    // -------------------------------------------------------------------------
    public Set<UUID> getEffectivePermissionIds(UUID userId) {
        return userRoles.findByUserId(userId).stream()
                .flatMap(ur -> rolePerms.findByRoleId(ur.getRoleId()).stream())
                .map(RolePermissionEntity::getPermissionId)
                .collect(Collectors.toSet());
    }

    public List<String> getEffectivePermissionNames(UUID userId) {
        return userRoles.findByUserId(userId).stream()
                .flatMap(ur -> rolePerms.findByRoleId(ur.getRoleId()).stream())
                .map(rp -> permissions.findById(rp.getPermissionId())
                        .map(p -> p.getResource() + "_" + p.getAction()).orElse(null))
                .filter(java.util.Objects::nonNull)
                .distinct()
                .collect(Collectors.toList());
    }

    public List<String> getUserRoleNames(UUID userId) {
        return userRoles.findByUserId(userId).stream()
                .map(ur -> roles.findById(ur.getRoleId())
                        .map(Role::getName).orElse(null))
                .filter(java.util.Objects::nonNull)
                .distinct()
                .collect(Collectors.toList());
    }

    // -------------------------------------------------------------------------
    // Session management (Section 7, 30.5)
    // -------------------------------------------------------------------------
    @Transactional
    public void revokeSession(UUID companyId, UUID userId, UUID sessionId, UUID actorId) {
        User u = getUser(companyId, userId);
        sessions.findById(sessionId).ifPresent(s -> {
            if (!s.getUserId().equals(userId)) {
                throw new AuthException(AuthErrorCode.FORBIDDEN);
            }
            s.setRevokedAt(Instant.now());
            sessions.save(s);
            refreshTokens.revokeBySession(sessionId, Instant.now());
        });
        audit.builder(AuditEventType.SESSION_REVOCATION)
                .actor("USER", actorId).company(companyId).target("USER", userId)
                .result("SUCCESS").record();
    }

    // =========================================================================
    private void assertSameCompany(UUID actual, UUID expected) {
        if (!actual.equals(expected)) {
            throw new AuthException(AuthErrorCode.CROSS_TENANT_DENIED);
        }
    }

    private String generatePassword() {
        byte[] bytes = new byte[18];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private PasswordHistory buildHistory(UUID userId, String hash) {
        PasswordHistory ph = new PasswordHistory();
        ph.setUserId(userId);
        ph.setPasswordHash(hash);
        ph.setCreatedAt(Instant.now());
        return ph;
    }
}
