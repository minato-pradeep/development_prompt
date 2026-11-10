package com.userrepo.auth.roles;

import com.userrepo.auth.audit.AuditEventType;
import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.permissions.PermissionRepository;
import com.userrepo.auth.roles.dto.CreateRoleRequest;
import com.userrepo.auth.roles.dto.UpdateRolePermissionsRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Role and permission management (Section 11). System roles cannot be deleted. */
@Service
public class RoleManagementService {

    private final RoleRepository           roles;
    private final RolePermissionRepository rolePerms;
    private final PermissionRepository     permissions;
    private final AuditLogService          audit;

    public RoleManagementService(RoleRepository roles,
                                 RolePermissionRepository rolePerms,
                                 PermissionRepository permissions,
                                 AuditLogService audit) {
        this.roles       = roles;
        this.rolePerms   = rolePerms;
        this.permissions = permissions;
        this.audit       = audit;
    }

    @Transactional
    public Role createRole(UUID companyId, CreateRoleRequest req, UUID actorId) {
        if (roles.findByCompanyIdAndName(companyId, req.name()).isPresent()) {
            throw new AuthException(AuthErrorCode.CONFLICT, "Role name already exists");
        }
        Role role = new Role();
        role.setCompanyId(companyId);
        role.setName(req.name());
        role.setDescription(req.description());
        role.setSystem(false);
        role.setCreatedAt(Instant.now());
        roles.save(role);
        audit.builder(AuditEventType.PERMISSION_CHANGED)
                .actor("USER", actorId).company(companyId).target("ROLE", role.getId())
                .result("SUCCESS").meta("action", "CREATE").record();
        return role;
    }

    @Transactional(readOnly = true)
    public List<Role> listRoles(UUID companyId) {
        return roles.findByCompanyId(companyId);
    }

    @Transactional
    public Role updateRole(UUID companyId, UUID roleId, CreateRoleRequest req, UUID actorId) {
        Role role = getRole(companyId, roleId);
        if (role.isSystem()) throw new AuthException(AuthErrorCode.FORBIDDEN, "Cannot modify system role name");
        role.setDescription(req.description());
        roles.save(role);
        return role;
    }

    @Transactional
    public void deleteRole(UUID companyId, UUID roleId, UUID actorId) {
        Role role = getRole(companyId, roleId);
        if (role.isSystem()) throw new AuthException(AuthErrorCode.FORBIDDEN, "System roles cannot be deleted");
        rolePerms.deleteAllByRoleId(roleId);
        roles.deleteById(roleId);
        audit.builder(AuditEventType.PERMISSION_CHANGED)
                .actor("USER", actorId).company(companyId).target("ROLE", roleId)
                .result("SUCCESS").meta("action", "DELETE").record();
    }

    @Transactional
    public void updatePermissions(UUID companyId, UUID roleId,
                                  UpdateRolePermissionsRequest req, UUID actorId) {
        Role role = getRole(companyId, roleId);
        rolePerms.deleteAllByRoleId(roleId);
        for (UpdateRolePermissionsRequest.PermissionLink link : req.permissions()) {
            permissions.findById(link.permissionId())
                    .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND, "Permission not found"));
            String scope = link.scope() != null ? link.scope() : "COMPANY";
            rolePerms.save(new RolePermissionEntity(roleId, link.permissionId(), scope));
        }
        audit.builder(AuditEventType.PERMISSION_CHANGED)
                .actor("USER", actorId).company(companyId).target("ROLE", roleId)
                .result("SUCCESS").meta("action", "UPDATE_PERMISSIONS").record();
    }

    private Role getRole(UUID companyId, UUID roleId) {
        Role role = roles.findById(roleId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND, "Role not found"));
        if (!role.getCompanyId().equals(companyId)) {
            throw new AuthException(AuthErrorCode.CROSS_TENANT_DENIED);
        }
        return role;
    }
}
