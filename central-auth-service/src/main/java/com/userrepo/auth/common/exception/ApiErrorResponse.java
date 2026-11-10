package com.userrepo.auth.common.exception;

import java.time.Instant;

/**
 * The Section 21 JSON error response shape:
 * <pre>
 * {
 *   "success": false,
 *   "error": { "code": "INVALID_CREDENTIALS", "message": "Invalid login credentials" },
 *   "timestamp": "2026-10-27T10:00:00Z",
 *   "traceId": "example-trace-id"
 * }
 * </pre>
 */
public record ApiErrorResponse(boolean success, ApiError error, Instant timestamp, String traceId) {

    public static ApiErrorResponse of(ApiError error, String traceId) {
        return new ApiErrorResponse(false, error, Instant.now(), traceId);
    }
}
