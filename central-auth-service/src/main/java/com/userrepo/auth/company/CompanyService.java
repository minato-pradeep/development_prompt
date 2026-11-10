package com.userrepo.auth.company;

import com.userrepo.auth.audit.AuditEventType;
import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.company.dto.*;
import com.userrepo.auth.crypto.Argon2PasswordHasher;
import com.userrepo.auth.roles.Role;
import com.userrepo.auth.roles.RoleRepository;
import com.userrepo.auth.users.User;
import com.userrepo.auth.users.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

/**
 * Company lifecycle management (Section 4, 5, 7). Only Super Admin may create
 * companies. Company and initial admin are created in ONE transaction so the
 * creation is atomic (Section 5, test 2).
 */
@Service
public class CompanyService {

    private static final int TEMP_PASSWORD_BYTES = 18; // 24 base64 chars

    private final CompanyRepository companies;
    private final CompanySettingsRepository settings;
    private final CompanyAuthSettingsRepository authSettings;
    private final UserRepository users;
    private final RoleRepository roles;
    private final Argon2PasswordHasher hasher;
    private final AuditLogService audit;
    private final SecureRandom random = new SecureRandom();

    public CompanyService(CompanyRepository companies,
                          CompanySettingsRepository settings,
                          CompanyAuthSettingsRepository authSettings,
                          UserRepository users,
                          RoleRepository roles,
                          Argon2PasswordHasher hasher,
                          AuditLogService audit) {
        this.companies = companies;
        this.settings = settings;
        this.authSettings = authSettings;
        this.users = users;
        this.roles = roles;
        this.hasher = hasher;
        this.audit = audit;
    }

    // -------------------------------------------------------------------------
    // Create company + initial Company Admin (one atomic transaction, Section 5)
    // -------------------------------------------------------------------------
    @Transactional
    public CreateCompanyResponse createCompany(CreateCompanyRequest req, UUID actorId) {
        if (companies.existsByCompanyCodeIgnoreCase(req.companyCode())) {
            throw new AuthException(AuthErrorCode.CONFLICT,
                    "Company code already exists");
        }

        // 1. Create company.
        Company company = new Company();
        company.setCompanyCode(req.companyCode().trim().toUpperCase());
        company.setName(req.name());
        company.setEmail(req.email());
        company.setContactNumber(req.contactNumber());
        company.setAddress(req.address());
        company.setCity(req.city());
        company.setState(req.state());
        company.setCountry(req.country());
        company.setPostalCode(req.postalCode());
        company.setWebsite(req.website());
        company.setTaxRegistration(req.taxRegistration());
        company.setStatus("ACTIVE");
        company.setTimeZone(req.timeZone() != null ? req.timeZone() : "UTC");
        company.setDefaultLanguage(req.defaultLanguage() != null ? req.defaultLanguage() : "en");
        company.setCreatedAt(Instant.now());
        companies.save(company);

        // 2. Default company settings.
        CompanySettings cs = new CompanySettings();
        cs.setCompanyId(company.getId());
        cs.setCreatedAt(Instant.now());
        settings.save(cs);

        CompanyAuthSettings cas = new CompanyAuthSettings();
        cas.setCompanyId(company.getId());
        cas.setCreatedAt(Instant.now());
        authSettings.save(cas);

        // 3. System COMPANY_ADMIN role.
        Role adminRole = new Role();
        adminRole.setCompanyId(company.getId());
        adminRole.setName("COMPANY_ADMIN");
        adminRole.setDescription("Company administrator system role");
        adminRole.setSystem(true);
        adminRole.setCreatedAt(Instant.now());
        roles.save(adminRole);

        // 4. Temporary password: use supplied or generate.
        CreateCompanyRequest.InitialAdminRequest adminReq = req.admin();
        boolean generated = (adminReq.temporaryPassword() == null
                || adminReq.temporaryPassword().isBlank());
        String plainPassword = generated ? generateSecurePassword() : adminReq.temporaryPassword();

        // 5. Create initial Company Admin user.
        User admin = new User();
        admin.setCompanyId(company.getId());
        admin.setUsername(adminReq.username());
        admin.setNormalizedUsername(adminReq.username().toLowerCase());
        admin.setEmail(adminReq.email());
        admin.setMobileNumber(adminReq.mobileNumber());
        admin.setFirstName(adminReq.firstName());
        admin.setLastName(adminReq.lastName());
        admin.setStatus("ACTIVE");
        admin.setPasswordHash(hasher.encode(plainPassword));
        admin.setMustChangePassword(true);
        admin.setMustEnrollTotp(true);
        admin.setCompanyAdmin(true);
        admin.setCreatedBy(actorId);
        admin.setCreatedAt(Instant.now());
        users.save(admin);

        // All steps in same transaction: if admin save fails, company rolls back (Section 5 test 2).

        audit.builder(AuditEventType.COMPANY_CREATED)
                .actor("PLATFORM_ADMIN", actorId)
                .target("COMPANY", company.getId())
                .result("SUCCESS")
                .meta("companyCode", company.getCompanyCode())
                .record();

        // Return generated password once if system-generated; never log or email it.
        return new CreateCompanyResponse(
                CompanyResponse.from(company),
                admin.getId(),
                admin.getUsername(),
                generated ? plainPassword : null);
    }

    @Transactional(readOnly = true)
    public Page<Company> listCompanies(Pageable pageable) {
        return companies.findAll(pageable);
    }

    @Transactional(readOnly = true)
    public Company getCompany(UUID id) {
        return companies.findById(id)
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND, "Company not found"));
    }

    @Transactional(readOnly = true)
    public Company getCompanyByCode(String code) {
        return companies.findByCompanyCodeIgnoreCase(code)
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND, "Company not found"));
    }

    @Transactional
    public Company updateCompany(UUID id, UpdateCompanyRequest req, UUID actorId) {
        Company company = getCompany(id);
        if (req.name() != null) company.setName(req.name());
        if (req.email() != null) company.setEmail(req.email());
        if (req.contactNumber() != null) company.setContactNumber(req.contactNumber());
        if (req.address() != null) company.setAddress(req.address());
        if (req.city() != null) company.setCity(req.city());
        if (req.state() != null) company.setState(req.state());
        if (req.country() != null) company.setCountry(req.country());
        if (req.postalCode() != null) company.setPostalCode(req.postalCode());
        if (req.website() != null) company.setWebsite(req.website());
        if (req.taxRegistration() != null) company.setTaxRegistration(req.taxRegistration());
        if (req.timeZone() != null) company.setTimeZone(req.timeZone());
        if (req.defaultLanguage() != null) company.setDefaultLanguage(req.defaultLanguage());
        companies.save(company);

        audit.builder(AuditEventType.COMPANY_UPDATED)
                .actor("PLATFORM_ADMIN", actorId).target("COMPANY", id).result("SUCCESS").record();
        return company;
    }

    @Transactional
    public void updateStatus(UUID id, String status, UUID actorId) {
        Company company = getCompany(id);
        String oldStatus = company.getStatus();
        company.setStatus(status);
        company.setSessionVersion(company.getSessionVersion() + 1); // invalidate existing tokens
        companies.save(company);

        AuditEventType evt = "ACTIVE".equals(status)
                ? AuditEventType.COMPANY_ACTIVATED : AuditEventType.COMPANY_DEACTIVATED;
        audit.builder(evt)
                .actor("PLATFORM_ADMIN", actorId).target("COMPANY", id).result("SUCCESS")
                .meta("oldStatus", oldStatus).meta("newStatus", status).record();
    }

    @Transactional(readOnly = true)
    public CompanyAuthSettings getAuthSettings(UUID companyId) {
        return authSettings.findByCompanyId(companyId)
                .orElseThrow(() -> new AuthException(AuthErrorCode.NOT_FOUND,
                        "Company auth settings not found"));
    }

    private String generateSecurePassword() {
        byte[] bytes = new byte[TEMP_PASSWORD_BYTES];
        random.nextBytes(bytes);
        // Use URL-safe base64; result is 24 chars, always meets min-length 12.
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
