package com.userrepo.auth.company.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record CompanyStatusRequest(
        @NotBlank @Pattern(regexp = "ACTIVE|INACTIVE|SUSPENDED") String status
) {}
