package com.userrepo.auth.users.dto;

import com.userrepo.auth.users.User;

import java.time.Instant;
import java.util.UUID;

public record UserResponse(
        UUID id, UUID companyId, String username, String email,
        String mobileNumber, String firstName, String lastName,
        String employeeCode, String department, String designation,
        String status, boolean totpEnabled, boolean companyAdmin,
        Instant lastLoginAt, Instant createdAt, Instant updatedAt
) {
    public static UserResponse from(User u) {
        return new UserResponse(u.getId(), u.getCompanyId(), u.getUsername(), u.getEmail(),
                u.getMobileNumber(), u.getFirstName(), u.getLastName(),
                u.getEmployeeCode(), u.getDepartment(), u.getDesignation(),
                u.getStatus(), u.isTotpEnabled(), u.isCompanyAdmin(),
                u.getLastLoginAt(), u.getCreatedAt(), u.getUpdatedAt());
    }
}
