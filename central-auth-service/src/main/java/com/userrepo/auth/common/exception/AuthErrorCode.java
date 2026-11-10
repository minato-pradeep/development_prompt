package com.userrepo.auth.common.exception;

/**
 * Stable, machine-readable error codes used across the API (Section 21).
 * The HTTP status is derived per-error so handlers stay consistent.
 */
public enum AuthErrorCode {

    // 400
    VALIDATION_ERROR(400, "Validation failed"),
    INVALID_REQUEST(400, "Invalid request"),
    INVALID_CLIENT(400, "Invalid or unknown client"),
    INVALID_REDIRECT_URI(400, "Redirect URI does not match a registered value"),
    INVALID_PKCE_VERIFIER(400, "PKCE verifier is missing or invalid"),

    // 401
    UNAUTHENTICATED(401, "Authentication is required"),
    INVALID_CREDENTIALS(401, "Invalid login credentials"),
    INVALID_TOTP(401, "Invalid TOTP code"),
    INVALID_REFRESH_TOKEN(401, "Invalid or expired refresh token"),
    INVALID_CHALLENGE(401, "Invalid or expired challenge"),
    STEP_UP_REQUIRED(401, "Fresh authentication (step-up) is required for this action"),
    TOTP_REPLAY(401, "TOTP code already used; wait for the next step"),

    // 403
    FORBIDDEN(403, "Access denied"),
    CROSS_TENANT_DENIED(403, "Access to another company's resources is denied"),
    PRIVILEGE_ESCALATION_DENIED(403, "Cannot assign a role with permissions you do not hold"),
    MFA_REQUIRED(403, "Multi-factor authentication is required"),
    BOOTSTRAP_DISABLED(403, "Bootstrap has already been completed"),

    // 404
    NOT_FOUND(404, "Resource not found"),

    // 409
    CONFLICT(409, "Request conflicts with current state"),
    USERNAME_TAKEN(409, "Username already exists in this company"),

    // 410
    ACCOUNT_LOCKED(410, "Account is temporarily locked; try again later"),

    // 423
    ONBOARDING_REQUIRED(423, "Account onboarding is required before access is granted"),

    // 429
    RATE_LIMITED(429, "Too many attempts; slow down"),

    // 500
    INTERNAL_ERROR(500, "An internal error occurred");

    private final int httpStatus;
    private final String defaultMessage;

    AuthErrorCode(int httpStatus, String defaultMessage) {
        this.httpStatus = httpStatus;
        this.defaultMessage = defaultMessage;
    }

    public int httpStatus() {
        return httpStatus;
    }

    public String defaultMessage() {
        return defaultMessage;
    }
}
