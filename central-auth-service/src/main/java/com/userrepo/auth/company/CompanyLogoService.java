package com.userrepo.auth.company;

import com.userrepo.auth.audit.AuditEventType;
import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.UUID;

@Service
public class CompanyLogoService {

    private final CompanyLogoRepository logoRepository;
    private final LogoStorageService storageService;
    private final AuditLogService audit;

    public CompanyLogoService(CompanyLogoRepository logoRepository,
                               LogoStorageService storageService,
                               AuditLogService audit) {
        this.logoRepository = logoRepository;
        this.storageService = storageService;
        this.audit = audit;
    }

    @Transactional
    public void uploadLogo(UUID companyId, MultipartFile file, UUID actorId) throws IOException {
        if (file.isEmpty()) {
            throw new AuthException(AuthErrorCode.VALIDATION_ERROR, "Logo file must not be empty");
        }
        byte[] bytes = file.getBytes();
        String declaredType = file.getContentType() != null ? file.getContentType() : "";

        // Validate, re-encode, strip metadata, and store.
        LogoStorageService.StoredLogo stored = storageService.store(
                companyId, file.getOriginalFilename(), declaredType, bytes);

        // Replace existing logo if present.
        logoRepository.findByCompanyId(companyId).ifPresent(old -> {
            storageService.delete(old.getStoredPath());
            logoRepository.delete(old);
        });

        CompanyLogo logo = new CompanyLogo();
        logo.setCompanyId(companyId);
        logo.setOriginalName(file.getOriginalFilename());
        logo.setStoredPath(stored.storedPath());
        logo.setContentType(stored.contentType());
        logo.setSizeBytes(stored.sizeBytes());
        logo.setWidthPx(stored.widthPx());
        logo.setHeightPx(stored.heightPx());
        logo.setUploadedBy(actorId);
        logo.setCreatedAt(Instant.now());
        logoRepository.save(logo);

        audit.builder(AuditEventType.COMPANY_LOGO_UPDATED)
                .actor("USER", actorId).company(companyId).result("SUCCESS").record();
    }

    @Transactional(readOnly = true)
    public ResponseEntity<byte[]> serveLogo(UUID companyId) throws IOException {
        CompanyLogo logo = logoRepository.findByCompanyId(companyId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND, "No logo found"));
        try (InputStream is = storageService.load(logo.getStoredPath())) {
            byte[] bytes = is.readAllBytes();
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_TYPE, logo.getContentType())
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "inline; filename=\"logo." + extension(logo.getContentType()) + "\"")
                    .body(bytes);
        }
    }

    private static String extension(String contentType) {
        return "image/png".equals(contentType) ? "png" : "jpg";
    }
}
