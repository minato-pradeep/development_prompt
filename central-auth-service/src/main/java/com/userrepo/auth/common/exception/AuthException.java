package com.userrepo.auth.common.exception;

/**
 * Application-level exception carrying a stable {@link AuthErrorCode} plus an
 * optional, user-facing message. The {@link GlobalExceptionHandler} converts
 * these to the Section 21 JSON error response.
 *
 * <p>Messages must never reveal whether a username, company or account exists
 * during unauthenticated login (Section 21). Use {@link AuthErrorCode} messages
 * carefully in those paths.
 */
public class AuthException extends RuntimeException {

    private final AuthErrorCode code;
    private final String message;

    public AuthException(AuthErrorCode code) {
        super(code.defaultMessage());
        this.code = code;
        this.message = code.defaultMessage();
    }

    public AuthException(AuthErrorCode code, String message) {
        super(message);
        this.code = code;
        this.message = message;
    }

    public AuthException(AuthErrorCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
        this.message = message;
    }

    public AuthErrorCode code() {
        return code;
    }

    @Override
    public String getMessage() {
        return message;
    }
}
