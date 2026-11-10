package com.userrepo.auth.roles;

import jakarta.persistence.*;

import java.io.Serializable;
import java.util.UUID;

/** User-to-Role assignment (Section 11). Composite PK. */
@Entity
@Table(name = "user_roles")
public class UserRoleEntity {

    @EmbeddedId
    private UserRoleId id;

    public UserRoleEntity() {}

    public UserRoleEntity(UUID userId, UUID roleId) {
        this.id = new UserRoleId(userId, roleId);
    }

    public UUID getUserId() { return id.getUserId(); }
    public UUID getRoleId() { return id.getRoleId(); }
    public UserRoleId getId() { return id; }
    public void setId(UserRoleId id) { this.id = id; }

    @Embeddable
    public static class UserRoleId implements Serializable {
        @Column(name = "user_id") private UUID userId;
        @Column(name = "role_id") private UUID roleId;

        public UserRoleId() {}
        public UserRoleId(UUID userId, UUID roleId) { this.userId = userId; this.roleId = roleId; }
        public UUID getUserId() { return userId; }
        public void setUserId(UUID userId) { this.userId = userId; }
        public UUID getRoleId() { return roleId; }
        public void setRoleId(UUID roleId) { this.roleId = roleId; }

        @Override public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof UserRoleId)) return false;
            UserRoleId that = (UserRoleId) o;
            return java.util.Objects.equals(userId, that.userId) &&
                   java.util.Objects.equals(roleId, that.roleId);
        }
        @Override public int hashCode() {
            return java.util.Objects.hash(userId, roleId);
        }
    }
}
