package com.userrepo.auth.common.exception;

/**
 * The {@code error} object inside a JSON error response (Section 21).
 *
 * @param code    stable, machine-readable error code (see {@link AuthErrorCode})
 * @param message human-readable message, safe to return to the client
 */
public record ApiError(String code, String message) {
    public static ApiError of(AuthErrorCode code) {
        return new ApiError(code.name(), code.defaultMessage());
    }

    public static ApiError of(AuthErrorCode code, String message) {
        return new ApiError(code.name(), message);
    }
}
