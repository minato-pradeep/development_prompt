package com.userrepo.auth.platform.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record PlatformTotpActivateRequest(
        @NotBlank @Size(max = 512) String challengeToken,
        @NotBlank @Pattern(regexp = "\\d{6}") String totpCode
) {
}
