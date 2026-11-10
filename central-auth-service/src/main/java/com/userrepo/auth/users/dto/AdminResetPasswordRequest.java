package com.userrepo.auth.users.dto;

import jakarta.validation.constraints.Size;

public record AdminResetPasswordRequest(
        /** If null/blank the system generates a secure temporary password. */
        @Size(min = 12, max = 128) String temporaryPassword
) {}
