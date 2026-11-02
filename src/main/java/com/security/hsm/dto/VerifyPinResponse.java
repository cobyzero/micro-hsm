package com.security.hsm.dto;

import java.time.Instant;

/**
 * Respuesta exitosa del endpoint POST /api/v1/account/verify-pin.
 */
public record VerifyPinResponse(
        String transactionId,
        String userId,
        boolean valid,
        String status,
        String pinBlockFormat,
        String keyCheckValue,
        Instant verifiedAt
) {}

