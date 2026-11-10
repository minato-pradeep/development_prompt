package com.userrepo.auth.company.dto;

import java.util.UUID;

/**
 * Response to Super Admin company creation. If the system generated the password it is
 * returned here ONCE and never stored in plaintext (Section 5). Never logged.
 */
public record CreateCompanyResponse(
        CompanyResponse company,
        UUID adminUserId,
        String adminUsername,
        /** Non-null only if the system generated the password; shown ONCE. Never email-sent. */
        String generatedTemporaryPassword
) {}
