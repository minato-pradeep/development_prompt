package com.userrepo.auth.authentication.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Tenant login request (Section 16, 30.4).
 * companyCode + username uniquely identifies a user across all tenants.
 */
public record LoginRequest(
        @NotBlank @Size(max = 32)  String companyCode,
        @NotBlank @Size(max = 64)  String username,
        @NotBlank @Size(max = 128) String password,
        /** Client identifier (Section 30.1). Required for native clients. */
        @Size(max = 128)           String clientId,
        /** Device identifier bound to the session (Section 30.5). */
        @Size(max = 128)           String deviceId,
        @Size(max = 32)            String platform,
        @Size(max = 64)            String appVersion
) {}
