package com.userrepo.auth.company.dto;

import com.userrepo.auth.company.Company;

import java.time.Instant;
import java.util.UUID;

public record CompanyResponse(
        UUID id, String companyCode, String name, String email,
        String contactNumber, String address, String city, String state,
        String country, String postalCode, String website, String taxRegistration,
        String status, String timeZone, String defaultLanguage,
        Instant createdAt, Instant updatedAt
) {
    public static CompanyResponse from(Company c) {
        return new CompanyResponse(c.getId(), c.getCompanyCode(), c.getName(), c.getEmail(),
                c.getContactNumber(), c.getAddress(), c.getCity(), c.getState(),
                c.getCountry(), c.getPostalCode(), c.getWebsite(), c.getTaxRegistration(),
                c.getStatus(), c.getTimeZone(), c.getDefaultLanguage(),
                c.getCreatedAt(), c.getUpdatedAt());
    }
}
