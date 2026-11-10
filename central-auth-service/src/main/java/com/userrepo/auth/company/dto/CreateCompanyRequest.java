package com.userrepo.auth.company.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/**
 * Super Admin creates a company with an initial Company Admin in one request (Section 5).
 */
public record CreateCompanyRequest(
        // Company fields
        @NotBlank @Size(max = 255) String name,
        @NotBlank @Size(max = 32)  String companyCode,
        @Email  @Size(max = 255)   String email,
        @Size(max = 32)            String contactNumber,
        @Size(max = 512)           String address,
        @Size(max = 128)           String city,
        @Size(max = 128)           String state,
        @Size(max = 64)            String country,
        @Size(max = 16)            String postalCode,
        @Size(max = 255)           String website,
        @Size(max = 128)           String taxRegistration,
        @Size(max = 64)            String timeZone,
        @Size(max = 16)            String defaultLanguage,

        // Initial Company Admin fields
        @NotNull @Valid InitialAdminRequest admin
) {
    public record InitialAdminRequest(
            @NotBlank @Size(max = 64)  String username,
            @NotBlank @Email @Size(max = 255) String email,
            @Size(max = 32)            String mobileNumber,
            /** If null/blank, the system generates a secure temporary password. */
            @Size(min = 12, max = 128) String temporaryPassword,
            @Size(max = 128)           String firstName,
            @Size(max = 128)           String lastName
    ) {}
}
