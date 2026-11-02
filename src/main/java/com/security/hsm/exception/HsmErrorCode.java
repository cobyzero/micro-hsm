package com.security.hsm.exception;

import org.springframework.http.HttpStatus;

/**
 * Catálogo estandarizado de códigos de error devueltos por el PaymentServer HSM
 * y su mapeo hacia códigos de estado HTTP para el cliente / backend principal.
 */
public enum HsmErrorCode {

    HSM_PIN_MISMATCH(
            "HSM_ERR_01",
            "El PIN actual ingresado es incorrecto.",
            HttpStatus.UNPROCESSABLE_ENTITY
    ),
    HSM_INVALID_PIN_BLOCK_FORMAT(
            "HSM_ERR_02",
            "Formato de PIN Block inválido (no cumple con el estándar ISO 9564).",
            HttpStatus.BAD_REQUEST
    ),
    HSM_PAN_BINDING_MISMATCH(
            "HSM_ERR_03",
            "El identificador de cuenta (PAN/UserId) embebido en el PIN Block no coincide con la cuenta transaccional.",
            HttpStatus.BAD_REQUEST
    ),
    HSM_RSA_DECRYPTION_FAILED(
            "HSM_ERR_04",
            "Fallo al descifrar el criptograma RSA-OAEP dentro del HSM (llave incorrecta o payload corrupto).",
            HttpStatus.BAD_REQUEST
    ),
    HSM_NEW_PIN_SAME_AS_CURRENT(
            "HSM_ERR_05",
            "El nuevo PIN debe ser diferente al PIN actual.",
            HttpStatus.UNPROCESSABLE_ENTITY
    ),
    HSM_WEAK_PIN_REJECTED(
            "HSM_ERR_06",
            "El nuevo PIN no cumple las políticas de seguridad (secuencia trivial o dígitos repetidos).",
            HttpStatus.UNPROCESSABLE_ENTITY
    ),
    HSM_COMMUNICATION_ERROR(
            "HSM_ERR_98",
            "Error de comunicación o sesión con el módulo criptográfico Utimaco PaymentServer.",
            HttpStatus.BAD_GATEWAY
    ),
    HSM_INTERNAL_ERROR(
            "HSM_ERR_99",
            "Error interno en el procesamiento criptográfico del HSM.",
            HttpStatus.INTERNAL_SERVER_ERROR
    );

    private final String code;
    private final String defaultMessage;
    private final HttpStatus httpStatus;

    HsmErrorCode(String code, String defaultMessage, HttpStatus httpStatus) {
        this.code = code;
        this.defaultMessage = defaultMessage;
        this.httpStatus = httpStatus;
    }

    public String getCode() {
        return code;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}

