package com.security.hsm.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Payload de entrada para POST /api/v1/account/verify-pin.
 * Permite verificar en el HSM si el PIN de 4 dígitos ingresado por el usuario
 * (cifrado con RSA-OAEP SHA-256 desde la App) coincide con el PIN actual de su cuenta.
 */
public record VerifyPinRequest(
        @NotBlank(message = "El campo userId es obligatorio")
        String userId,

        @Pattern(regexp = "^[0-9]{8,19}$", message = "El panOrAccountNumber debe contener entre 8 y 19 dígitos numéricos")
        String panOrAccountNumber,

        @NotBlank(message = "El campo encryptedPin (Base64) es obligatorio")
        String encryptedPin,

        String storedPinBlockUnderLmk
) {
    public String resolveIsoAccountNumber() {
        String source = (panOrAccountNumber != null && !panOrAccountNumber.isBlank())
                ? panOrAccountNumber
                : userId;
        String digitsOnly = source.replaceAll("\\D", "");
        if (digitsOnly.length() >= 13) {
            return digitsOnly.substring(digitsOnly.length() - 13, digitsOnly.length() - 1);
        }
        return String.format("%12s", digitsOnly).replace(' ', '0');
    }
}

