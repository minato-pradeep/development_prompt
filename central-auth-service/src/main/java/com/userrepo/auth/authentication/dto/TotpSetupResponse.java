package com.userrepo.auth.authentication.dto;

public record TotpSetupResponse(
        String otpauthUri,
        String secretGrouped,   // groups of 4 for manual entry (Section 30.4)
        String challengeToken
) {}
