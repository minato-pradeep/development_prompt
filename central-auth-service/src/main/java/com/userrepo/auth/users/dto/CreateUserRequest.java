package com.userrepo.auth.users.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateUserRequest(
        @NotBlank @Size(max = 64)  String username,
        @NotBlank @Email @Size(max = 255) String email,
        @Size(max = 32)  String mobileNumber,
        @Size(max = 128) String firstName,
        @Size(max = 128) String lastName,
        @Size(max = 64)  String employeeCode,
        @Size(max = 128) String department,
        @Size(max = 128) String designation,
        /** If null/blank a secure temporary password is generated. */
        @Size(min = 12, max = 128) String temporaryPassword
) {}
