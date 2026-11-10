package com.userrepo.auth.permissions.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterPermissionRequest(
        @NotBlank @Size(max = 64) String resource,
        @NotBlank @Size(max = 64) String action,
        @Size(max = 255) String description,
        @Size(max = 128) String registeredBy
) {}
