package com.userrepo.auth.company.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

public record UpdateCompanyRequest(
        @Size(max = 255) String name,
        @Email @Size(max = 255) String email,
        @Size(max = 32) String contactNumber,
        @Size(max = 512) String address,
        @Size(max = 128) String city,
        @Size(max = 128) String state,
        @Size(max = 64) String country,
        @Size(max = 16) String postalCode,
        @Size(max = 255) String website,
        @Size(max = 128) String taxRegistration,
        @Size(max = 64) String timeZone,
        @Size(max = 16) String defaultLanguage
) {}
