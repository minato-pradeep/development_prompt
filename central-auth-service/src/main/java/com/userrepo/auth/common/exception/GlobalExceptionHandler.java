package com.userrepo.auth.common.exception;

import com.userrepo.auth.common.TraceIds;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.stream.Collectors;

/**
 * Translates exceptions into the Section 21 JSON error response. Responses and
 * timing must be indistinguishable where account existence must not be leaked.
 * Internal details (stack traces, SQL, key names) are never returned to clients.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ApiErrorResponse> handleAuthException(AuthException ex, HttpServletRequest request) {
        AuthErrorCode code = ex.code();
        log.warn("[{}] auth error {}: {}", TraceIds.current(), code, ex.getMessage());
        return ResponseEntity.status(code.httpStatus())
                .body(ApiErrorResponse.of(ApiError.of(code, ex.getMessage()), TraceIds.current()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidation(MethodArgumentNotValidException ex) {
        String detail = ex.getBindingResult().getFieldErrors().stream()
                .map(this::describe)
                .collect(Collectors.joining("; "));
        String message = detail.isBlank() ? AuthErrorCode.VALIDATION_ERROR.defaultMessage() : detail;
        log.warn("[{}] validation error: {}", TraceIds.current(), message);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiErrorResponse.of(ApiError.of(AuthErrorCode.VALIDATION_ERROR, message), TraceIds.current()));
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<ApiErrorResponse> handleTypeMismatch(MethodArgumentTypeMismatchException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(ApiErrorResponse.of(ApiError.of(AuthErrorCode.INVALID_REQUEST), TraceIds.current()));
    }

    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiErrorResponse> handleAuthentication(AuthenticationException ex) {
        // Spring Security authentication failures (e.g. bad JWT). Generic message only.
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(ApiErrorResponse.of(ApiError.of(AuthErrorCode.UNAUTHENTICATED), TraceIds.current()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorResponse> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(ApiErrorResponse.of(ApiError.of(AuthErrorCode.FORBIDDEN), TraceIds.current()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleUnexpected(Exception ex) {
        // Never leak internals; log the detail server-side only.
        log.error("[{}] unexpected error", TraceIds.current(), ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ApiErrorResponse.of(ApiError.of(AuthErrorCode.INTERNAL_ERROR), TraceIds.current()));
    }

    private String describe(FieldError fe) {
        return fe.getField() + ": " + fe.getDefaultMessage();
    }
}
