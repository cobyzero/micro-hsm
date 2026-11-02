package com.security.hsm.service.hsm;

import com.security.hsm.config.HsmProperties;
import com.security.hsm.crypto.Iso9564PinBlockCodec;
import com.security.hsm.dto.PinPublicKeyResponse;
import com.security.hsm.exception.HsmErrorCode;
import com.security.hsm.exception.HsmOperationException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Clase base abstracta que implementa el flujo criptográfico estándar del PaymentServer
 * utilizando objetos Key opacos del proveedor JCE/PKCS#11 (Utimaco Hardware / Simulador).
 *
 * Garantiza que tanto el modo SIMULATOR como el modo PKCS11 ejecuten exactamente la misma
 * semántica de validación, traducción ISO 9564 Formato 4 y limpieza de memoria (zeroization).
 */
public abstract class AbstractJceHsmAdapter implements HsmCryptoOperations {

    private static final Logger log = LoggerFactory.getLogger(AbstractJceHsmAdapter.class);

    protected final HsmProperties properties;
    private final Instant keyInitializedAt = Instant.now();

    /**
     * Registro en memoria (para pruebas rápidas en desarrollo cuando el backend principal no envía
     * storedPinBlockUnderLmk en el primer cambio). Por defecto inicializa cuentas de prueba con PIN "1234".
     */
    private final Map<String, String> simulatedAccountPinBlocks = new ConcurrentHashMap<>();

    protected AbstractJceHsmAdapter(HsmProperties properties) {
        this.properties = properties;
    }

    protected abstract PublicKey resolveRsaPublicKey();

    protected abstract PrivateKey resolveRsaPrivateKey();

    protected abstract SecretKey resolveLmkAesKey();

    /**
     * Proveedor JCE opcional (ej. SunPKCS11-Utimaco en modo hardware/contenedor PKCS#11).
     */
    protected abstract String getJceProviderName();

    @Override
    public PinPublicKeyResponse getRsaPublicKey() {
        PublicKey publicKey = resolveRsaPublicKey();
        byte[] encodedX509 = publicKey.getEncoded();
        String base64Der = Base64.getEncoder().encodeToString(encodedX509);
        String pem = formatAsPem(encodedX509);

        return new PinPublicKeyResponse(
                properties.getKeyId(),
                "RSA-OAEP-256",
                "ISO-9564-FORMAT-4",
                pem,
                base64Der,
                keyInitializedAt
        );
    }

    @Override
    public String translateAndChangePin(
            String userId,
            String isoAccount12Digits,
            String encryptedCurrentPinB64,
            String encryptedNewPinB64,
            String storedPinBlockUnderLmk
    ) {
        byte[] decryptedCurrentBlock = null;
        byte[] decryptedNewBlock = null;
        char[] currentPinFromClient = null;
        char[] expectedCurrentPin = null;
        char[] newPinFromClient = null;

        try {
            // 1. Descifrar ambos bloques RSA-OAEP (SHA-256) dentro del HSM usando la llave privada RSA-2048
            decryptedCurrentBlock = decryptRsaOaepSha256(encryptedCurrentPinB64);
            decryptedNewBlock = decryptRsaOaepSha256(encryptedNewPinB64);

            // 2. Extraer y validar estructura ISO 9564 + enlace de cuenta (PAN/Account 12 dígitos)
            currentPinFromClient = Iso9564PinBlockCodec.extractAndVerifyPinFromClientBlock(
                    decryptedCurrentBlock, isoAccount12Digits
            );
            newPinFromClient = Iso9564PinBlockCodec.extractAndVerifyPinFromClientBlock(
                    decryptedNewBlock, isoAccount12Digits
            );

            // 3. Resolver el PIN Block actual bajo LMK (desde el request del backend o registro inicial en simulador)
            String effectiveStoredLmkBlock = resolveEffectiveStoredPinBlock(
                    userId, isoAccount12Digits, storedPinBlockUnderLmk
            );

            // 4. Descifrar el PIN Block almacenado bajo LMK y comparar en tiempo constante contra currentPinFromClient
            expectedCurrentPin = Iso9564PinBlockCodec.decryptIsoFormat4UnderLmk(
                    effectiveStoredLmkBlock, isoAccount12Digits, resolveLmkAesKey()
            );

            if (!constantTimeEquals(currentPinFromClient, expectedCurrentPin)) {
                throw new HsmOperationException(HsmErrorCode.HSM_PIN_MISMATCH);
            }

            // 5. Aplicar reglas de seguridad PCI-PIN al nuevo PIN (no igual al anterior, no trivial)
            Iso9564PinBlockCodec.enforceNewPinPolicy(currentPinFromClient, newPinFromClient);

            // 6. Traducir el nuevo PIN a un bloque ISO 9564 Formato 4 cifrado bajo la llave maestra LMK AES-128
            String newPinBlockUnderLmk = Iso9564PinBlockCodec.encryptIsoFormat4UnderLmk(
                    newPinFromClient, isoAccount12Digits, resolveLmkAesKey()
            );

            // Actualizar en el store de simulación para pruebas consecutivas
            simulatedAccountPinBlocks.put(userId, newPinBlockUnderLmk);

            return newPinBlockUnderLmk;
        } finally {
            // 7. Volatilidad de datos: limpieza inmediata en memoria de cualquier buffer sensible
            Iso9564PinBlockCodec.zeroize(decryptedCurrentBlock);
            Iso9564PinBlockCodec.zeroize(decryptedNewBlock);
            Iso9564PinBlockCodec.zeroize(currentPinFromClient);
            Iso9564PinBlockCodec.zeroize(expectedCurrentPin);
            Iso9564PinBlockCodec.zeroize(newPinFromClient);
        }
    }

    @Override
    public boolean verifyPin(
            String userId,
            String isoAccount12Digits,
            String encryptedPinB64,
            String storedPinBlockUnderLmk
    ) {
        byte[] decryptedBlock = null;
        char[] pinFromClient = null;
        char[] expectedPin = null;

        try {
            decryptedBlock = decryptRsaOaepSha256(encryptedPinB64);
            pinFromClient = Iso9564PinBlockCodec.extractAndVerifyPinFromClientBlock(
                    decryptedBlock, isoAccount12Digits
            );

            String effectiveStoredLmkBlock = resolveEffectiveStoredPinBlock(
                    userId, isoAccount12Digits, storedPinBlockUnderLmk
            );

            expectedPin = Iso9564PinBlockCodec.decryptIsoFormat4UnderLmk(
                    effectiveStoredLmkBlock, isoAccount12Digits, resolveLmkAesKey()
            );

            if (!constantTimeEquals(pinFromClient, expectedPin)) {
                throw new HsmOperationException(HsmErrorCode.HSM_PIN_MISMATCH);
            }
            return true;
        } finally {
            Iso9564PinBlockCodec.zeroize(decryptedBlock);
            Iso9564PinBlockCodec.zeroize(pinFromClient);
            Iso9564PinBlockCodec.zeroize(expectedPin);
        }
    }

    @Override
    public String getLmkKeyCheckValue() {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, resolveLmkAesKey());
            byte[] zeros = new byte[16];
            byte[] encryptedZeros = cipher.doFinal(zeros);
            return HexFormat.of().withUpperCase().formatHex(encryptedZeros, 0, 3);
        } catch (Exception e) {
            return "000000";
        }
    }

    /**
     * Descifra el criptograma Base64 usando RSA/ECB/OAEPWithSHA-256AndMGF1Padding.
     * Compatible tanto con WebCrypto API (navegadores/apps móviles) como con JCE/PKCS#11.
     */
    protected byte[] decryptRsaOaepSha256(String base64Ciphertext) {
        byte[] cipherBytes;
        try {
            cipherBytes = Base64.getDecoder().decode(base64Ciphertext);
        } catch (IllegalArgumentException e) {
            throw new HsmOperationException(
                    HsmErrorCode.HSM_RSA_DECRYPTION_FAILED,
                    "El criptograma enviado no tiene una codificación Base64 válida."
            );
        }

        try {
            Cipher rsaCipher;
            OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            );

            if (getJceProviderName() != null) {
                try {
                    rsaCipher = Cipher.getInstance("RSA/ECB/OAEPPadding", getJceProviderName());
                    rsaCipher.init(Cipher.DECRYPT_MODE, resolveRsaPrivateKey(), oaepParams);
                } catch (Exception exTransform) {
                    log.debug("[HSM-RSA] Intento con RSA/ECB/OAEPPadding falló ({}), reintentando con RSA/ECB/OAEPWithSHA-256AndMGF1Padding...", exTransform.getMessage());
                    rsaCipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding", getJceProviderName());
                    rsaCipher.init(Cipher.DECRYPT_MODE, resolveRsaPrivateKey());
                }
            } else {
                rsaCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
                rsaCipher.init(Cipher.DECRYPT_MODE, resolveRsaPrivateKey(), oaepParams);
            }

            return rsaCipher.doFinal(cipherBytes);
        } catch (Exception e) {
            log.error("[HSM-RSA] Fallo al descifrar criptograma RSA-OAEP (longitud bytes={}, provider={}): {}",
                    cipherBytes.length, getJceProviderName(), e.getMessage(), e);
            throw new HsmOperationException(HsmErrorCode.HSM_RSA_DECRYPTION_FAILED, e);
        }
    }

    /**
     * Si el backend principal envía storedPinBlockUnderLmk, se valida directamente contra él.
     * Si no se envía (ej. prueba inicial contra el simulador), aprovisiona un PIN inicial por defecto ("1234")
     * cifrado bajo la LMK para esa cuenta.
     */
    private String resolveEffectiveStoredPinBlock(String userId, String isoAccount12Digits, String storedPinBlockUnderLmk) {
        if (storedPinBlockUnderLmk != null && !storedPinBlockUnderLmk.isBlank()) {
            return storedPinBlockUnderLmk.trim().toUpperCase();
        }
        return simulatedAccountPinBlocks.computeIfAbsent(userId, id -> {
            char[] defaultInitialPin = new char[]{'1', '2', '3', '4'};
            try {
                return Iso9564PinBlockCodec.encryptIsoFormat4UnderLmk(
                        defaultInitialPin, isoAccount12Digits, resolveLmkAesKey()
                );
            } finally {
                Iso9564PinBlockCodec.zeroize(defaultInitialPin);
            }
        });
    }

    private boolean constantTimeEquals(char[] a, char[] b) {
        if (a == null || b == null || a.length != b.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }

    private String formatAsPem(byte[] derBytes) {
        String base64Wrapped = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(derBytes);
        return "-----BEGIN PUBLIC KEY-----\n" + base64Wrapped + "\n-----END PUBLIC KEY-----";
    }
}

