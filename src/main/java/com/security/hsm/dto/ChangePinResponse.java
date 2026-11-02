package com.security.hsm.dto;

import java.time.Instant;

/**
 * Respuesta exitosa del endpoint POST /api/v1/account/change-pin.
 * Devuelve el nuevo PIN Block traducido por el HSM y cifrado bajo la llave maestra local (LMK AES-128)
 * en formato ISO 9564 Formato 4 para que el backend principal lo persista de forma segura en Base de Datos.
 */
public record ChangePinResponse(
        String transactionId,
        String userId,
        String status,
        String pinBlockFormat,
        String newPinBlockUnderLmk,
        String keyCheckValue,
        Instant processedAt
) {}

