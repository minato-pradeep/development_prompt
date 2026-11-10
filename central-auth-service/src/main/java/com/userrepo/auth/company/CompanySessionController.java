package com.userrepo.auth.company;

import com.userrepo.auth.audit.AuditLog;
import com.userrepo.auth.audit.AuditLogRepository;
import com.userrepo.auth.common.ApiResponse;
import com.userrepo.auth.common.TraceIds;
import com.userrepo.auth.tokens.JwtClaims;
import com.userrepo.auth.users.UserManagementService;
import com.userrepo.auth.users.UserSession;
import com.userrepo.auth.users.UserSessionRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/** Company Admin session listing, revocation and audit-log access (Section 7, 16). */
@RestController
@RequestMapping("/api/v1/company")
@PreAuthorize("hasRole('COMPANY_ADMIN')")
@Tag(name = "Company Administration", description = "Session and audit management")
public class CompanySessionController {

    private final UserSessionRepository sessions;
    private final UserManagementService  userService;
    private final AuditLogRepository     auditLogs;

    public CompanySessionController(UserSessionRepository sessions,
                                     UserManagementService userService,
                                     AuditLogRepository auditLogs) {
        this.sessions  = sessions;
        this.userService = userService;
        this.auditLogs = auditLogs;
    }

    /** GET /api/v1/company/sessions */
    @GetMapping("/sessions")
    @Operation(summary = "List all active sessions in the company")
    public ResponseEntity<ApiResponse<List<UserSession>>> listSessions(
            @AuthenticationPrincipal Jwt jwt) {
        UUID cid = UUID.fromString(jwt.getClaimAsString(JwtClaims.COMPANY_ID));
        return ResponseEntity.ok(ApiResponse.ok(
                sessions.findByCompanyIdAndRevokedAtIsNull(cid), TraceIds.current()));
    }

    /** DELETE /api/v1/company/sessions/{id} */
    @DeleteMapping("/sessions/{id}")
    @Operation(summary = "Revoke a specific session")
    public ResponseEntity<ApiResponse<Void>> revokeSession(
            @PathVariable UUID id, @AuthenticationPrincipal Jwt jwt) {
        UUID cid = UUID.fromString(jwt.getClaimAsString(JwtClaims.COMPANY_ID));
        UUID aid = UUID.fromString(jwt.getSubject());
        sessions.findById(id).ifPresent(s ->
                userService.revokeSession(cid, s.getUserId(), id, aid));
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    /** GET /api/v1/company/audit-logs */
    @GetMapping("/audit-logs")
    @Operation(summary = "Company audit logs (most recent first)")
    public ResponseEntity<ApiResponse<List<AuditLog>>> auditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @AuthenticationPrincipal Jwt jwt) {
        UUID cid = UUID.fromString(jwt.getClaimAsString(JwtClaims.COMPANY_ID));
        List<AuditLog> logs = auditLogs.findAll(
                (root, q, cb) -> cb.equal(root.get("companyId"), cid),
                PageRequest.of(page, size, Sort.by("createdAt").descending())
        ).getContent();
        return ResponseEntity.ok(ApiResponse.ok(logs, TraceIds.current()));
    }
}
