package com.userrepo.auth.tokens;

/**
 * Issuer/audience scope for a token (Section 4). Platform (Super Admin) tokens
 * use a distinct issuer scope and audience, and are never accepted by tenant
 * APIs; tenant tokens are never accepted by platform APIs.
 */
public enum TokenIssuerScope {
    PLATFORM,
    TENANT
}
