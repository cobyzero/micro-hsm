package com.security.hsm.exception;

import com.security.hsm.dto.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Mapeo centralizado de errores del HSM y validaciones de entrada a respuestas HTTP estandarizadas.
 * Garantiza que ninguna traza criptográfica sensible se filtre al exterior.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(HsmOperationException.class)
    public ResponseEntity<ApiErrorResponse> handleHsmOperationException(
            HsmOperationException ex,
            HttpServletRequest request
    ) {
        HsmErrorCode errorCode = ex.getErrorCode();
        HttpStatus status = errorCode.getHttpStatus();

        log.warn("[HSM-ERROR] code={} status={} path={} msg={} cause={}",
                errorCode.getCode(), status.value(), request.getRequestURI(), ex.getMessage(),
                ex.getCause() != null ? ex.getCause().toString() : "none");

        ApiErrorResponse body = new ApiErrorResponse(
                errorCode.getCode(),
                ex.getMessage(),
                status.value(),
                request.getRequestURI(),
                Instant.now(),
                Map.of()
        );
        return ResponseEntity.status(status).body(body);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiErrorResponse> handleValidationExceptions(
            MethodArgumentNotValidException ex,
            HttpServletRequest request
    ) {
        Map<String, String> fieldErrors = new LinkedHashMap<>();
        for (FieldError fieldError : ex.getBindingResult().getFieldErrors()) {
            fieldErrors.put(fieldError.getField(), fieldError.getDefaultMessage());
        }

        ApiErrorResponse body = new ApiErrorResponse(
                "VALIDATION_ERROR",
                "El payload de la solicitud contiene campos inválidos o incompletos.",
                HttpStatus.BAD_REQUEST.value(),
                request.getRequestURI(),
                Instant.now(),
                fieldErrors
        );
        return ResponseEntity.badRequest().body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> handleUnexpectedException(
            Exception ex,
            HttpServletRequest request
    ) {
        log.error("[UNEXPECTED-ERROR] path={}", request.getRequestURI(), ex);

        ApiErrorResponse body = new ApiErrorResponse(
                HsmErrorCode.HSM_INTERNAL_ERROR.getCode(),
                HsmErrorCode.HSM_INTERNAL_ERROR.getDefaultMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                request.getRequestURI(),
                Instant.now(),
                Map.of()
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}

