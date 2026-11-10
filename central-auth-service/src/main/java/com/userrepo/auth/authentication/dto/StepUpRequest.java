package com.userrepo.auth.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record StepUpRequest(
        @NotBlank @Pattern(regexp = "\\d{6}") String totpCode
) {}
