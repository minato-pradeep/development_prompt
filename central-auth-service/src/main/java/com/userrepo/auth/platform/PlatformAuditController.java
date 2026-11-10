package com.userrepo.auth.platform;

import com.userrepo.auth.audit.AuditLog;
import com.userrepo.auth.audit.AuditLogRepository;
import com.userrepo.auth.common.ApiResponse;
import com.userrepo.auth.common.TraceIds;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/** Platform-wide audit log access for Super Admin (Section 4, 16). */
@RestController
@RequestMapping("/api/v1/platform")
@PreAuthorize("hasRole('SUPER_ADMIN')")
@Tag(name = "Platform", description = "Super Admin platform management")
public class PlatformAuditController {

    private final AuditLogRepository auditLogs;

    public PlatformAuditController(AuditLogRepository auditLogs) {
        this.auditLogs = auditLogs;
    }

    /** GET /api/v1/platform/audit-logs */
    @GetMapping("/audit-logs")
    @Operation(summary = "Platform-wide audit logs")
    public ResponseEntity<ApiResponse<Page<AuditLog>>> auditLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        Page<AuditLog> result = auditLogs.findAll(
                PageRequest.of(page, size, Sort.by("createdAt").descending()));
        return ResponseEntity.ok(ApiResponse.ok(result, TraceIds.current()));
    }
}
