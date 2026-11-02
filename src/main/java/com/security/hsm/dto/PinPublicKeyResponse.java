package com.security.hsm.dto;

import java.time.Instant;

/**
 * Respuesta del endpoint GET /api/v1/security/pin-key.
 * Expone la llave pública RSA-2048 del HSM en formato X.509/PEM para que
 * las aplicaciones (Web/App) cifren el PIN Block con RSA-OAEP (SHA-256).
 */
public record PinPublicKeyResponse(
        String keyId,
        String algorithm,
        String pinBlockFormat,
        String publicKeyPem,
        String publicKeyBase64,
        Instant issuedAt
) {}

