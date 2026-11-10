package com.userrepo.auth.users;

import com.userrepo.auth.common.ApiResponse;
import com.userrepo.auth.common.TraceIds;
import com.userrepo.auth.tokens.JwtClaims;
import com.userrepo.auth.users.dto.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/** Company Admin user management (Section 7, 16). */
@RestController
@RequestMapping("/api/v1/users")
@PreAuthorize("hasRole('COMPANY_ADMIN')")
@Tag(name = "Users", description = "User management within a company")
public class UserController {

    private final UserManagementService service;

    public UserController(UserManagementService service) {
        this.service = service;
    }

    private UUID companyId(Jwt jwt) {
        return UUID.fromString(jwt.getClaimAsString(JwtClaims.COMPANY_ID));
    }

    @PostMapping
    @Operation(summary = "Create a user")
    public ResponseEntity<ApiResponse<UserResponse>> create(
            @Valid @RequestBody CreateUserRequest req,
            @AuthenticationPrincipal Jwt jwt) {
        UUID cid = companyId(jwt);
        UUID aid = UUID.fromString(jwt.getSubject());
        return ResponseEntity.status(201).body(ApiResponse.ok(
                UserResponse.from(service.createUser(cid, req, aid)), TraceIds.current()));
    }

    @GetMapping
    @Operation(summary = "List users in company")
    public ResponseEntity<ApiResponse<Page<UserResponse>>> list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @AuthenticationPrincipal Jwt jwt) {
        UUID cid = companyId(jwt);
        Page<UserResponse> result = service.listUsers(cid,
                PageRequest.of(page, size, Sort.by("createdAt").descending()))
                .map(UserResponse::from);
        return ResponseEntity.ok(ApiResponse.ok(result, TraceIds.current()));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get user details")
    public ResponseEntity<ApiResponse<UserResponse>> get(
            @PathVariable UUID id, @AuthenticationPrincipal Jwt jwt) {
        return ResponseEntity.ok(ApiResponse.ok(
                UserResponse.from(service.getUser(companyId(jwt), id)), TraceIds.current()));
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update user")
    public ResponseEntity<ApiResponse<UserResponse>> update(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateUserRequest req,
            @AuthenticationPrincipal Jwt jwt) {
        UUID cid = companyId(jwt);
        UUID aid = UUID.fromString(jwt.getSubject());
        return ResponseEntity.ok(ApiResponse.ok(
                UserResponse.from(service.updateUser(cid, id, req, aid)), TraceIds.current()));
    }

    @PatchMapping("/{id}/status")
    @Operation(summary = "Activate or deactivate a user")
    public ResponseEntity<ApiResponse<Void>> status(
            @PathVariable UUID id,
            @Valid @RequestBody StatusRequest req,
            @AuthenticationPrincipal Jwt jwt) {
        UUID cid = companyId(jwt);
        UUID aid = UUID.fromString(jwt.getSubject());
        service.updateStatus(cid, id, req.status(), aid);
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    @PostMapping("/{id}/unlock")
    @Operation(summary = "Unlock a locked user account")
    public ResponseEntity<ApiResponse<Void>> unlock(
            @PathVariable UUID id, @AuthenticationPrincipal Jwt jwt) {
        UUID cid = companyId(jwt);
        UUID aid = UUID.fromString(jwt.getSubject());
        service.unlockUser(cid, id, aid);
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    @PostMapping("/{id}/reset-password")
    @Operation(summary = "Admin reset user password")
    public ResponseEntity<ApiResponse<String>> resetPassword(
            @PathVariable UUID id,
            @Valid @RequestBody AdminResetPasswordRequest req,
            @AuthenticationPrincipal Jwt jwt) {
        UUID cid = companyId(jwt);
        UUID aid = UUID.fromString(jwt.getSubject());
        String generated = service.adminResetPassword(cid, id, req, aid);
        return ResponseEntity.ok(ApiResponse.ok(generated, TraceIds.current()));
    }

    @PutMapping("/{id}/roles")
    @Operation(summary = "Assign roles to a user")
    public ResponseEntity<ApiResponse<Void>> assignRoles(
            @PathVariable UUID id,
            @Valid @RequestBody AssignRolesRequest req,
            @AuthenticationPrincipal Jwt jwt) {
        UUID cid = companyId(jwt);
        UUID aid = UUID.fromString(jwt.getSubject());
        service.assignRoles(cid, id, req.roleIds(), aid);
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    /** GET /api/v1/users/me — current user's own profile (Section 15). */
    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get own profile")
    public ResponseEntity<ApiResponse<UserResponse>> me(@AuthenticationPrincipal Jwt jwt) {
        UUID userId = UUID.fromString(jwt.getSubject());
        UUID cid    = UUID.fromString(jwt.getClaimAsString(JwtClaims.COMPANY_ID));
        return ResponseEntity.ok(ApiResponse.ok(
                UserResponse.from(service.getUser(cid, userId)), TraceIds.current()));
    }

    /** GET /api/v1/users/me/permissions (Section 15). */
    @GetMapping("/me/permissions")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get own effective permissions")
    public ResponseEntity<ApiResponse<java.util.List<String>>> myPermissions(
            @AuthenticationPrincipal Jwt jwt) {
        UUID userId = UUID.fromString(jwt.getSubject());
        return ResponseEntity.ok(ApiResponse.ok(
                service.getEffectivePermissionNames(userId), TraceIds.current()));
    }
}
