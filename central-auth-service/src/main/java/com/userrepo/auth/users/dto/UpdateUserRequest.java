package com.userrepo.auth.users.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

public record UpdateUserRequest(
        @Email @Size(max = 255) String email,
        @Size(max = 32)  String mobileNumber,
        @Size(max = 128) String firstName,
        @Size(max = 128) String lastName,
        @Size(max = 64)  String employeeCode,
        @Size(max = 128) String department,
        @Size(max = 128) String designation
) {}
