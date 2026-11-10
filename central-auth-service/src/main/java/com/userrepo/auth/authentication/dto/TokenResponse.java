package com.userrepo.auth.authentication.dto;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        long   expiresInSeconds
) {}
