package com.userrepo.auth.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ForgotPasswordRequest(
        @NotBlank @Size(max = 32)  String companyCode,
        @NotBlank @Size(max = 64)  String username
) {}
