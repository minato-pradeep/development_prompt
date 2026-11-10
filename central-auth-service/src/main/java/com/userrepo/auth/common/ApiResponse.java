package com.userrepo.auth.common;

import java.time.Instant;

/**
 * Consistent success envelope mirroring the Section 21 error shape:
 * <pre>
 * { "success": true, "data": ..., "timestamp": "...", "traceId": "..." }
 * </pre>
 */
public record ApiResponse<T>(boolean success, T data, Instant timestamp, String traceId) {

    public static <T> ApiResponse<T> ok(T data, String traceId) {
        return new ApiResponse<>(true, data, Instant.now(), traceId);
    }
}
