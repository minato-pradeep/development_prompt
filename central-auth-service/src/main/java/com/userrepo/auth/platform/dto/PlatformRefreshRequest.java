package com.userrepo.auth.platform.dto;

import jakarta.validation.constraints.NotBlank;

public record PlatformRefreshRequest(@NotBlank String refreshToken) {
}
