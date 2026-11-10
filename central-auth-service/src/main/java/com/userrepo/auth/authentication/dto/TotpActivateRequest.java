package com.userrepo.auth.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record TotpActivateRequest(
        @NotBlank @Size(max = 512) String challengeToken,
        @NotBlank @Pattern(regexp = "\\d{6}") String totpCode
) {}
