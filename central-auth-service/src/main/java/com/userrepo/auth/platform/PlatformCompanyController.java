package com.userrepo.auth.platform;

import com.userrepo.auth.common.ApiResponse;
import com.userrepo.auth.common.TraceIds;
import com.userrepo.auth.company.Company;
import com.userrepo.auth.company.CompanyService;
import com.userrepo.auth.company.dto.*;
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

/**
 * Platform Super Admin company management endpoints (Section 16).
 * All require ROLE_SUPER_ADMIN via a platform-scope token.
 */
@RestController
@RequestMapping("/api/v1/platform/companies")
@PreAuthorize("hasRole('SUPER_ADMIN')")
@Tag(name = "Platform Companies", description = "Super Admin company management")
public class PlatformCompanyController {

    private final CompanyService companyService;

    public PlatformCompanyController(CompanyService companyService) {
        this.companyService = companyService;
    }

    /** POST /api/v1/platform/companies — create company + initial admin. */
    @PostMapping
    @Operation(summary = "Create company and initial Company Admin")
    public ResponseEntity<ApiResponse<CreateCompanyResponse>> createCompany(
            @Valid @RequestBody CreateCompanyRequest request,
            @AuthenticationPrincipal Jwt jwt) {
        UUID actorId = UUID.fromString(jwt.getSubject());
        CreateCompanyResponse result = companyService.createCompany(request, actorId);
        return ResponseEntity.status(201).body(ApiResponse.ok(result, TraceIds.current()));
    }

    /** GET /api/v1/platform/companies — list all companies. */
    @GetMapping
    @Operation(summary = "List all companies")
    public ResponseEntity<ApiResponse<Page<CompanyResponse>>> listCompanies(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        Page<CompanyResponse> result = companyService
                .listCompanies(PageRequest.of(page, size, Sort.by("createdAt").descending()))
                .map(CompanyResponse::from);
        return ResponseEntity.ok(ApiResponse.ok(result, TraceIds.current()));
    }

    /** GET /api/v1/platform/companies/{id} — company details. */
    @GetMapping("/{id}")
    @Operation(summary = "Get company details")
    public ResponseEntity<ApiResponse<CompanyResponse>> getCompany(@PathVariable UUID id) {
        return ResponseEntity.ok(ApiResponse.ok(
                CompanyResponse.from(companyService.getCompany(id)), TraceIds.current()));
    }

    /** PUT /api/v1/platform/companies/{id} — update company. */
    @PutMapping("/{id}")
    @Operation(summary = "Update company details")
    public ResponseEntity<ApiResponse<CompanyResponse>> updateCompany(
            @PathVariable UUID id,
            @Valid @RequestBody UpdateCompanyRequest request,
            @AuthenticationPrincipal Jwt jwt) {
        UUID actorId = UUID.fromString(jwt.getSubject());
        Company updated = companyService.updateCompany(id, request, actorId);
        return ResponseEntity.ok(ApiResponse.ok(CompanyResponse.from(updated), TraceIds.current()));
    }

    /** PATCH /api/v1/platform/companies/{id}/status — activate or deactivate. */
    @PatchMapping("/{id}/status")
    @Operation(summary = "Activate or deactivate a company")
    public ResponseEntity<ApiResponse<Void>> updateStatus(
            @PathVariable UUID id,
            @Valid @RequestBody CompanyStatusRequest request,
            @AuthenticationPrincipal Jwt jwt) {
        UUID actorId = UUID.fromString(jwt.getSubject());
        companyService.updateStatus(id, request.status(), actorId);
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }
}
