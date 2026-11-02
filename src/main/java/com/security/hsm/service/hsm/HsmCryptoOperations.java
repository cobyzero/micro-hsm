package com.security.hsm.service.hsm;

import com.security.hsm.dto.PinPublicKeyResponse;

/**
 * Contrato modular hacia el HSM de Utimaco (PaymentServer Simulator o Appliance Físico).
 *
 * El backend invoca esta interfaz en modo Blind Routing:
 * recibe criptogramas en Base64 y delega toda la validación y traducción criptográfica
 * al HSM sin exponer jamás el PIN en claro al microservicio.
 */
public interface HsmCryptoOperations {

    /**
     * Obtiene la Llave Pública RSA-2048 del HSM en formato X.509/PEM.
     */
    PinPublicKeyResponse getRsaPublicKey();

    /**
     * Ejecuta la operación transaccional de Cambio de PIN dentro del entorno seguro del HSM:
     * 1. Descifra encryptedCurrentPinBase64 y encryptedNewPinBase64 dentro del HSM usando la llave privada RSA-2048 (RSA-OAEP SHA-256).
     * 2. Verifica el formato ISO 9564 y el vínculo con los 12 dígitos de la cuenta (isoAccount12Digits).
     * 3. Valida que el PIN actual coincida con el PIN registrado bajo LMK (storedPinBlockUnderLmk).
     * 4. Traduce el nuevo PIN a un PIN Block ISO 9564 Formato 4 cifrado bajo la llave maestra local (LMK AES-128).
     * 5. Limpia (zeroize) todos los registros volátiles internos.
     *
     * @param userId                  Identificador del usuario
     * @param isoAccount12Digits      12 dígitos de cuenta (PAN sin dígito verificador) según ISO 9564
     * @param encryptedCurrentPinB64  PIN Block actual cifrado con RSA-OAEP (Base64)
     * @param encryptedNewPinB64      Nuevo PIN Block cifrado con RSA-OAEP (Base64)
     * @param storedPinBlockUnderLmk  PIN Block actual almacenado en BD bajo LMK (32 hex chars), o null si usa el store del simulador
     * @return El nuevo PIN Block (32 caracteres hexadecimales) cifrado bajo la LMK del HSM
     */
    String translateAndChangePin(
            String userId,
            String isoAccount12Digits,
            String encryptedCurrentPinB64,
            String encryptedNewPinB64,
            String storedPinBlockUnderLmk
    );

    /**
     * Verifica dentro del HSM si el PIN cifrado con RSA-OAEP coincide con el PIN actual
     * de la cuenta del usuario (almacenado bajo LMK o en el registro del simulador).
     */
    boolean verifyPin(
            String userId,
            String isoAccount12Digits,
            String encryptedPinB64,
            String storedPinBlockUnderLmk
    );

    /**
     * Devuelve el Key Check Value (KCV) de 6 caracteres hexadecimales de la llave maestra LMK activa.
     */
    String getLmkKeyCheckValue();
}

