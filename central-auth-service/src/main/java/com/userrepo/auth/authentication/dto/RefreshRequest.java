package com.userrepo.auth.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RefreshRequest(
        @NotBlank String refreshToken,
        @Size(max = 128) String clientId,
        @Size(max = 128) String deviceId
) {}
