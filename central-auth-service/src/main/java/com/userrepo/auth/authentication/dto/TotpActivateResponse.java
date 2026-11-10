package com.userrepo.auth.authentication.dto;

import java.util.List;

public record TotpActivateResponse(
        String accessToken,
        String refreshToken,
        long   expiresInSeconds,
        List<String> recoveryCodes   // shown once only (Section 6)
) {}
