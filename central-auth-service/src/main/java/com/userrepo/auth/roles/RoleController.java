package com.userrepo.auth.roles;

import com.userrepo.auth.common.ApiResponse;
import com.userrepo.auth.common.TraceIds;
import com.userrepo.auth.permissions.Permission;
import com.userrepo.auth.permissions.PermissionRepository;
import com.userrepo.auth.roles.dto.CreateRoleRequest;
import com.userrepo.auth.roles.dto.UpdateRolePermissionsRequest;
import com.userrepo.auth.tokens.JwtClaims;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/** Roles and permissions endpoints (Section 16). */
@RestController
@Tag(name = "Roles & Permissions", description = "Role and permission management")
public class RoleController {

    private final RoleManagementService service;
    private final PermissionRepository  permissions;

    public RoleController(RoleManagementService service, PermissionRepository permissions) {
        this.service     = service;
        this.permissions = permissions;
    }

    private UUID cid(Jwt jwt) {
        return UUID.fromString(jwt.getClaimAsString(JwtClaims.COMPANY_ID));
    }

    @PostMapping("/api/v1/roles")
    @PreAuthorize("hasRole('COMPANY_ADMIN')")
    @Operation(summary = "Create a role")
    public ResponseEntity<ApiResponse<Role>> create(
            @Valid @RequestBody CreateRoleRequest req, @AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.status(201).body(ApiResponse.ok(
                service.createRole(cid(jwt), req, UUID.fromString(jwt.getSubject())),
                TraceIds.current()));
    }

    @GetMapping("/api/v1/roles")
    @PreAuthorize("hasRole('COMPANY_ADMIN')")
    @Operation(summary = "List roles for the company")
    public ResponseEntity<ApiResponse<List<Role>>> list(@AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(ApiResponse.ok(service.listRoles(cid(jwt)), TraceIds.current()));
    }

    @PutMapping("/api/v1/roles/{id}")
    @PreAuthorize("hasRole('COMPANY_ADMIN')")
    @Operation(summary = "Update role")
    public ResponseEntity<ApiResponse<Role>> update(
            @PathVariable UUID id, @Valid @RequestBody CreateRoleRequest req,
            @AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(ApiResponse.ok(
                service.updateRole(cid(jwt), id, req, UUID.fromString(jwt.getSubject())),
                TraceIds.current()));
    }

    @DeleteMapping("/api/v1/roles/{id}")
    @PreAuthorize("hasRole('COMPANY_ADMIN')")
    @Operation(summary = "Delete a non-system role")
    public ResponseEntity<ApiResponse<Void>> delete(
            @PathVariable UUID id, @AuthenticationPrincipal Jwt jwt) {
        service.deleteRole(cid(jwt), id, UUID.fromString(jwt.getSubject()));
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    @PutMapping("/api/v1/roles/{id}/permissions")
    @PreAuthorize("hasRole('COMPANY_ADMIN')")
    @Operation(summary = "Update permissions for a role")
    public ResponseEntity<ApiResponse<Void>> updatePermissions(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateRolePermissionsRequest req,
            @AuthenticationPrincipal Jwt jwt) {
        service.updatePermissions(cid(jwt), id, req, UUID.fromString(jwt.getSubject()));
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    /** GET /api/v1/permissions — global catalog (Section 11). */
    @GetMapping("/api/v1/permissions")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "List global permission catalog")
    public ResponseEntity<ApiResponse<List<Permission>>> listPermissions() {
        return ResponseEntity.ok(ApiResponse.ok(permissions.findAll(), TraceIds.current()));
    }

    /** POST /api/v1/platform/permissions — register new permission (Super Admin / service client). */
    @PostMapping("/api/v1/platform/permissions")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    @Operation(summary = "Register a new global permission (Super Admin)")
    public ResponseEntity<ApiResponse<Permission>> registerPermission(
            @Valid @RequestBody com.userrepo.auth.permissions.dto.RegisterPermissionRequest req) {
        Permission p = new Permission();
        p.setResource(req.resource());
        p.setAction(req.action());
        p.setDescription(req.description());
        p.setRegisteredBy(req.registeredBy());
        p.setCreatedAt(java.time.Instant.now());
        Permission saved = permissions.save(p);
        return ResponseEntity.status(201).body(ApiResponse.ok(saved, TraceIds.current()));
    }
}
