package com.security.hsm.dto;

import java.time.Instant;
import java.util.Map;

/**
 * Respuesta HTTP estandarizada para errores del HSM o de validación de entrada.
 */
public record ApiErrorResponse(
        String errorCode,
        String message,
        int httpStatus,
        String path,
        Instant timestamp,
        Map<String, String> details
) {}

