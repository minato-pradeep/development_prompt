package com.userrepo.auth.company;

import com.userrepo.auth.common.ApiResponse;
import com.userrepo.auth.common.TraceIds;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.company.dto.*;
import com.userrepo.auth.tokens.JwtClaims;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.util.UUID;

/**
 * Company Admin self-service company profile, settings and logo endpoints (Section 7, 16).
 * A Company Admin may only access their own company's resources.
 */
@RestController
@RequestMapping("/api/v1/company")
@PreAuthorize("hasRole('COMPANY_ADMIN')")
@Tag(name = "Company Administration", description = "Company profile, settings and logo management")
public class CompanyProfileController {

    private final CompanyService companyService;
    private final CompanyLogoService logoService;

    public CompanyProfileController(CompanyService companyService,
                                    CompanyLogoService logoService) {
        this.companyService = companyService;
        this.logoService = logoService;
    }

    private UUID companyIdFromJwt(Jwt jwt) {
        String raw = jwt.getClaimAsString(JwtClaims.COMPANY_ID);
        if (raw == null) throw new AuthException(AuthErrorCode.FORBIDDEN);
        return UUID.fromString(raw);
    }

    /** GET /api/v1/company/profile */
    @GetMapping("/profile")
    @Operation(summary = "Get company profile")
    public ResponseEntity<ApiResponse<CompanyResponse>> getProfile(@AuthenticationPrincipal Jwt jwt) {
        UUID companyId = companyIdFromJwt(jwt);
        return ResponseEntity.ok(ApiResponse.ok(
                CompanyResponse.from(companyService.getCompany(companyId)), TraceIds.current()));
    }

    /** PUT /api/v1/company/profile */
    @PutMapping("/profile")
    @Operation(summary = "Update company profile (allowed fields only)")
    public ResponseEntity<ApiResponse<CompanyResponse>> updateProfile(
            @Valid @RequestBody UpdateCompanyRequest req,
            @AuthenticationPrincipal Jwt jwt) {
        UUID companyId = companyIdFromJwt(jwt);
        UUID actorId = UUID.fromString(jwt.getSubject());
        Company updated = companyService.updateCompany(companyId, req, actorId);
        return ResponseEntity.ok(ApiResponse.ok(CompanyResponse.from(updated), TraceIds.current()));
    }

    /** GET /api/v1/company/settings */
    @GetMapping("/settings")
    @Operation(summary = "Get company settings")
    public ResponseEntity<ApiResponse<CompanyAuthSettings>> getSettings(
            @AuthenticationPrincipal Jwt jwt) {
        UUID companyId = companyIdFromJwt(jwt);
        return ResponseEntity.ok(ApiResponse.ok(
                companyService.getAuthSettings(companyId), TraceIds.current()));
    }

    /** POST /api/v1/company/logo — upload or replace logo (PNG/JPEG only). */
    @PostMapping(value = "/logo", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @Operation(summary = "Upload or replace company logo")
    public ResponseEntity<ApiResponse<Void>> uploadLogo(
            @RequestParam("file") MultipartFile file,
            @AuthenticationPrincipal Jwt jwt) throws IOException {
        UUID companyId = companyIdFromJwt(jwt);
        UUID actorId = UUID.fromString(jwt.getSubject());
        logoService.uploadLogo(companyId, file, actorId);
        return ResponseEntity.ok(ApiResponse.ok(null, TraceIds.current()));
    }

    /** GET /api/v1/company/logo — download logo (authorized only). */
    @GetMapping("/logo")
    @Operation(summary = "Download company logo")
    public ResponseEntity<byte[]> getLogo(@AuthenticationPrincipal Jwt jwt) throws IOException {
        UUID companyId = companyIdFromJwt(jwt);
        return logoService.serveLogo(companyId);
    }
}
