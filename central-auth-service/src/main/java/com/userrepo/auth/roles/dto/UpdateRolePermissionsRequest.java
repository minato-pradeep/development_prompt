package com.userrepo.auth.roles.dto;

import jakarta.validation.constraints.NotNull;

import java.util.List;
import java.util.UUID;

public record UpdateRolePermissionsRequest(
        @NotNull List<PermissionLink> permissions
) {
    public record PermissionLink(UUID permissionId, String scope) {}
}
