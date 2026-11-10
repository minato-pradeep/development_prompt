package com.userrepo.auth.users.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record StatusRequest(
        @NotBlank @Pattern(regexp = "ACTIVE|INACTIVE|DISABLED") String status
) {}
