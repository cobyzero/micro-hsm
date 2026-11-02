package com.security.hsm.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Payload de entrada para POST /api/v1/account/change-pin.
 *
 * El microservicio opera bajo un esquema Blind Routing (enrutamiento ciego):
 * - encryptedCurrentPin y encryptedNewPin vienen cifrados desde la App/Web con la llave pública RSA-OAEP del HSM.
 * - storedPinBlockUnderLmk (opcional) es el PIN Block actual del usuario que el backend principal tiene guardado
 *   en Base de Datos cifrado bajo la llave maestra local (LMK AES-128) en formato ISO 9564 Formato 4.
 *   Si es la primera vez o se usa el registro en el simulador, puede omitirse o enviarse para verificación estricta.
 */
public record ChangePinRequest(
        @NotBlank(message = "El campo userId es obligatorio")
        String userId,

        @Pattern(regexp = "^[0-9]{8,19}$", message = "El panOrAccountNumber debe contener entre 8 y 19 dígitos numéricos")
        String panOrAccountNumber,

        @NotBlank(message = "El campo encryptedCurrentPin (Base64) es obligatorio")
        String encryptedCurrentPin,

        @NotBlank(message = "El campo encryptedNewPin (Base64) es obligatorio")
        String encryptedNewPin,

        String storedPinBlockUnderLmk
) {
    /**
     * Obtiene el identificador numérico de 12 dígitos (Account Number Field según ISO 9564)
     * derivado del panOrAccountNumber o del userId para vincular criptográficamente el PIN Block.
     */
    public String resolveIsoAccountNumber() {
        String source = (panOrAccountNumber != null && !panOrAccountNumber.isBlank())
                ? panOrAccountNumber
                : userId;
        String digitsOnly = source.replaceAll("\\D", "");
        if (digitsOnly.length() >= 13) {
            // Estándar ISO 9564: los 12 dígitos más a la derecha excluyendo el dígito verificador final (check digit)
            return digitsOnly.substring(digitsOnly.length() - 13, digitsOnly.length() - 1);
        }
        // Si tiene 12 dígitos o menos, se rellena con ceros a la izquierda hasta 12 dígitos
        return String.format("%12s", digitsOnly).replace(' ', '0');
    }
}

