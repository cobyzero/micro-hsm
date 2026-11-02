package com.security.hsm.exception;

/**
 * Excepción de dominio lanzada ante cualquier condición de error reportada por el HSM.
 * Nunca expone datos sensibles ni trazas criptográficas internas hacia el exterior.
 */
public class HsmOperationException extends RuntimeException {

    private final HsmErrorCode errorCode;

    public HsmOperationException(HsmErrorCode errorCode) {
        super(errorCode.getDefaultMessage());
        this.errorCode = errorCode;
    }

    public HsmOperationException(HsmErrorCode errorCode, String customMessage) {
        super(customMessage);
        this.errorCode = errorCode;
    }

    public HsmOperationException(HsmErrorCode errorCode, Throwable cause) {
        super(errorCode.getDefaultMessage(), cause);
        this.errorCode = errorCode;
    }

    public HsmErrorCode getErrorCode() {
        return errorCode;
    }
}

