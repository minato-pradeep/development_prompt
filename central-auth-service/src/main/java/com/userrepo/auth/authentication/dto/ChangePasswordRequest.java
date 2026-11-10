package com.userrepo.auth.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest(
        @NotBlank @Size(max = 512) String challengeToken,   // onboarding challenge (or null for authenticated change)
        @NotBlank @Size(min = 1, max = 128) String currentPassword,
        @NotBlank @Size(min = 12, max = 128) String newPassword
) {}
