package com.userrepo.auth.roles;

import jakarta.persistence.*;

import java.io.Serializable;
import java.util.UUID;

/** Role-to-Permission link with scope (OWN | DEPARTMENT | COMPANY). Section 11. */
@Entity
@Table(name = "role_permissions")
public class RolePermissionEntity {

    @EmbeddedId
    private RolePermissionId id;

    @Column(name = "scope", nullable = false)
    private String scope = "COMPANY";

    public RolePermissionEntity() {}

    public RolePermissionEntity(UUID roleId, UUID permissionId, String scope) {
        this.id = new RolePermissionId(roleId, permissionId);
        this.scope = scope;
    }

    public UUID getRoleId() { return id.getRoleId(); }
    public UUID getPermissionId() { return id.getPermissionId(); }
    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }
    public RolePermissionId getId() { return id; }
    public void setId(RolePermissionId id) { this.id = id; }

    @Embeddable
    public static class RolePermissionId implements Serializable {
        @Column(name = "role_id")       private UUID roleId;
        @Column(name = "permission_id") private UUID permissionId;

        public RolePermissionId() {}
        public RolePermissionId(UUID roleId, UUID permissionId) {
            this.roleId = roleId; this.permissionId = permissionId;
        }
        public UUID getRoleId() { return roleId; }
        public void setRoleId(UUID r) { this.roleId = r; }
        public UUID getPermissionId() { return permissionId; }
        public void setPermissionId(UUID p) { this.permissionId = p; }

        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof RolePermissionId)) return false;
            RolePermissionId that = (RolePermissionId) o;
            return java.util.Objects.equals(roleId, that.roleId) &&
                   java.util.Objects.equals(permissionId, that.permissionId);
        }
        @Override public int hashCode() {
            return java.util.Objects.hash(roleId, permissionId);
        }
    }
}
