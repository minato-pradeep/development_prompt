package com.userrepo.auth.platform.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record PlatformLoginRequest(
        @NotBlank @Size(max = 64) String username,
        @NotBlank @Size(min = 1, max = 128) String password
) {
}
