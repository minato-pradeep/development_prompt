package com.userrepo.auth.company;

import com.userrepo.auth.audit.AuditLogService;
import com.userrepo.auth.common.exception.AuthErrorCode;
import com.userrepo.auth.common.exception.AuthException;
import com.userrepo.auth.company.dto.CreateCompanyRequest;
import com.userrepo.auth.company.dto.CreateCompanyResponse;
import com.userrepo.auth.crypto.Argon2PasswordHasher;
import com.userrepo.auth.roles.Role;
import com.userrepo.auth.roles.RoleRepository;
import com.userrepo.auth.users.User;
import com.userrepo.auth.users.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CompanyServiceTest {

    @Mock CompanyRepository companyRepo;
    @Mock CompanySettingsRepository settingsRepo;
    @Mock CompanyAuthSettingsRepository authSettingsRepo;
    @Mock UserRepository userRepo;
    @Mock RoleRepository roleRepo;
    @Mock AuditLogService audit;

    private CompanyService service;
    private final Argon2PasswordHasher hasher = new Argon2PasswordHasher();

    @BeforeEach
    void setUp() {
        service = new CompanyService(companyRepo, settingsRepo, authSettingsRepo,
                userRepo, roleRepo, hasher, audit);

        AuditLogService.AuditEntryBuilder builder =
                mock(AuditLogService.AuditEntryBuilder.class, RETURNS_SELF);
        // lenient: not all tests reach audit.builder
        lenient().when(audit.builder(any())).thenReturn(builder);

        lenient().when(companyRepo.save(any())).thenAnswer(inv -> {
            Company c = inv.getArgument(0);
            if (c.getId() == null) {
                setField(c, "id", UUID.randomUUID());
            }
            return c;
        });
        lenient().when(settingsRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(authSettingsRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(roleRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
        lenient().when(userRepo.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    @Test
    void createCompany_withGeneratedPassword_returnsGeneratedPassword() {
        when(companyRepo.existsByCompanyCodeIgnoreCase("ACME")).thenReturn(false);
        CreateCompanyResponse resp =
                service.createCompany(buildRequest("ACME", null), UUID.randomUUID());
        assertThat(resp.company().companyCode()).isEqualTo("ACME");
        assertThat(resp.generatedTemporaryPassword()).isNotNull();
        assertThat(resp.generatedTemporaryPassword().length()).isGreaterThanOrEqualTo(12);
    }

    @Test
    void createCompany_withSuppliedPassword_doesNotReturnGeneratedPassword() {
        when(companyRepo.existsByCompanyCodeIgnoreCase("TVS")).thenReturn(false);
        CreateCompanyResponse resp =
                service.createCompany(buildRequest("TVS", "SuppliedPass123!"), UUID.randomUUID());
        assertThat(resp.generatedTemporaryPassword()).isNull();
    }

    @Test
    void createCompany_adminMustChangePasswordAndEnrollTotp() {
        when(companyRepo.existsByCompanyCodeIgnoreCase("MACS")).thenReturn(false);
        service.createCompany(buildRequest("MACS", null), UUID.randomUUID());
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepo).save(captor.capture());
        assertThat(captor.getValue().isMustChangePassword()).isTrue();
        assertThat(captor.getValue().isMustEnrollTotp()).isTrue();
        assertThat(captor.getValue().isCompanyAdmin()).isTrue();
    }

    @Test
    void createCompany_savesSettingsAndAuthSettings() {
        when(companyRepo.existsByCompanyCodeIgnoreCase("XYZ")).thenReturn(false);
        service.createCompany(buildRequest("XYZ", null), UUID.randomUUID());
        verify(settingsRepo).save(any(CompanySettings.class));
        verify(authSettingsRepo).save(any(CompanyAuthSettings.class));
    }

    @Test
    void createCompany_createsSystemCompanyAdminRole() {
        when(companyRepo.existsByCompanyCodeIgnoreCase("TST")).thenReturn(false);
        service.createCompany(buildRequest("TST", null), UUID.randomUUID());
        ArgumentCaptor<Role> captor = ArgumentCaptor.forClass(Role.class);
        verify(roleRepo).save(captor.capture());
        assertThat(captor.getValue().getName()).isEqualTo("COMPANY_ADMIN");
        assertThat(captor.getValue().isSystem()).isTrue();
    }

    @Test
    void createCompany_duplicateCode_throwsConflict() {
        when(companyRepo.existsByCompanyCodeIgnoreCase("DUPE")).thenReturn(true);
        assertThatThrownBy(() ->
                service.createCompany(buildRequest("DUPE", null), UUID.randomUUID()))
                .isInstanceOf(AuthException.class)
                .satisfies(e ->
                        assertThat(((AuthException) e).code()).isEqualTo(AuthErrorCode.CONFLICT));
    }

    @Test
    void createCompany_passwordStoredAsHash() {
        when(companyRepo.existsByCompanyCodeIgnoreCase("HASH")).thenReturn(false);
        service.createCompany(buildRequest("HASH", "PlainPassword123!"), UUID.randomUUID());
        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(userRepo).save(captor.capture());
        assertThat(captor.getValue().getPasswordHash()).startsWith("$argon2id$");
        assertThat(captor.getValue().getPasswordHash()).doesNotContain("PlainPassword123!");
    }

    private CreateCompanyRequest buildRequest(String code, String password) {
        return new CreateCompanyRequest(
                "Test Company", code, "test@company.com",
                null, null, null, null, null, null, null, null, "UTC", "en",
                new CreateCompanyRequest.InitialAdminRequest(
                        "admin", "admin@company.com", null, password, "Admin", "User")
        );
    }

    private static void setField(Object obj, String name, Object value) {
        try {
            Field f = obj.getClass().getDeclaredField(name);
            f.setAccessible(true);
            f.set(obj, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
