package com.userrepo.auth.platform.dto;

public record TokenPairResponse(
        String accessToken,
        String refreshToken,
        long expiresInSeconds
) {
}
