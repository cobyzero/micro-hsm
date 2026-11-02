package com.security.hsm.service.hsm;

import com.security.hsm.config.HsmProperties;
import com.security.hsm.crypto.Iso9564PinBlockCodec;
import com.security.hsm.dto.PinPublicKeyResponse;
import com.security.hsm.exception.HsmErrorCode;
import com.security.hsm.exception.HsmOperationException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.security.MessageDigest;
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
     * Descifra el criptograma Base64 usando RSA-OAEP con SHA-256 y MGF1(SHA-256).
     * En SunPKCS11 (donde P11RSACipher solo soporta NoPadding y PKCS1Padding),
     * ejecuta la operación C^d mod n en el HSM vía CKM_RSA_X_509 (RSA/ECB/NoPadding)
     * y decodifica el padding OAEP RFC 8017 con limpieza inmediata en memoria.
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
            if (getJceProviderName() != null) {
                // Operación privada asimétrica ejecutada 100% dentro del HSM físico/simulador
                Cipher rawRsaCipher = Cipher.getInstance("RSA/ECB/NoPadding", getJceProviderName());
                rawRsaCipher.init(Cipher.DECRYPT_MODE, resolveRsaPrivateKey());
                byte[] em = rawRsaCipher.doFinal(cipherBytes);
                try {
                    return decodeOaepSha256(em);
                } finally {
                    Iso9564PinBlockCodec.zeroize(em);
                }
            } else {
                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
                OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                        "SHA-256",
                        "MGF1",
                        MGF1ParameterSpec.SHA256,
                        PSource.PSpecified.DEFAULT
                );
                rsaCipher.init(Cipher.DECRYPT_MODE, resolveRsaPrivateKey(), oaepParams);
                return rsaCipher.doFinal(cipherBytes);
            }
        } catch (Exception e) {
            log.error("[HSM-RSA] Fallo al descifrar criptograma RSA-OAEP (longitud bytes={}, provider={}): {}",
                    cipherBytes.length, getJceProviderName(), e.getMessage(), e);
            throw new HsmOperationException(HsmErrorCode.HSM_RSA_DECRYPTION_FAILED, e);
        }
    }

    /**
     * Decodifica el padding RSA-OAEP con SHA-256 y MGF1(SHA-256) según RFC 8017
     * a partir del mensaje codificado (EM) devuelto por la operación CKM_RSA_X_509 en el HSM.
     */
    private byte[] decodeOaepSha256(byte[] rawEm) throws Exception {
        byte[] em = rawEm;
        if (em.length < 256) {
            byte[] padded = new byte[256];
            System.arraycopy(em, 0, padded, 256 - em.length, em.length);
            em = padded;
        }

        int k = em.length;
        int hLen = 32; // SHA-256 digest length
        if (k < 2 * hLen + 2) {
            throw new BadPaddingException("Decryption error: EM too short");
        }
        if (em[0] != 0x00) {
            throw new BadPaddingException("Decryption error: First byte not 0x00");
        }

        byte[] maskedSeed = Arrays.copyOfRange(em, 1, 1 + hLen);
        byte[] maskedDB = Arrays.copyOfRange(em, 1 + hLen, k);
        byte[] seed = null;
        byte[] db = null;
        byte[] seedMask = null;
        byte[] dbMask = null;

        try {
            seedMask = mgf1Sha256(maskedDB, hLen);
            seed = new byte[hLen];
            for (int i = 0; i < hLen; i++) {
                seed[i] = (byte) (maskedSeed[i] ^ seedMask[i]);
            }

            dbMask = mgf1Sha256(seed, maskedDB.length);
            db = new byte[maskedDB.length];
            for (int i = 0; i < maskedDB.length; i++) {
                db[i] = (byte) (maskedDB[i] ^ dbMask[i]);
            }

            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] lHash = md.digest(new byte[0]);

            int diff = 0;
            for (int i = 0; i < hLen; i++) {
                diff |= (db[i] ^ lHash[i]);
            }
            if (diff != 0) {
                throw new BadPaddingException("Decryption error: lHash mismatch");
            }

            int sepIdx = -1;
            for (int i = hLen; i < db.length; i++) {
                if (db[i] == 0x01) {
                    sepIdx = i;
                    break;
                } else if (db[i] != 0x00) {
                    throw new BadPaddingException("Decryption error: Invalid padding byte");
                }
            }

            if (sepIdx == -1) {
                throw new BadPaddingException("Decryption error: 0x01 separator not found");
            }

            return Arrays.copyOfRange(db, sepIdx + 1, db.length);
        } finally {
            Iso9564PinBlockCodec.zeroize(maskedSeed);
            Iso9564PinBlockCodec.zeroize(maskedDB);
            Iso9564PinBlockCodec.zeroize(seed);
            Iso9564PinBlockCodec.zeroize(db);
            Iso9564PinBlockCodec.zeroize(seedMask);
            Iso9564PinBlockCodec.zeroize(dbMask);
        }
    }

    private byte[] mgf1Sha256(byte[] seed, int maskLen) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        int hLen = 32;
        byte[] mask = new byte[maskLen];
        byte[] counterBytes = new byte[4];
        int count = 0;
        int generated = 0;
        while (generated < maskLen) {
            counterBytes[0] = (byte) ((count >> 24) & 0xFF);
            counterBytes[1] = (byte) ((count >> 16) & 0xFF);
            counterBytes[2] = (byte) ((count >> 8) & 0xFF);
            counterBytes[3] = (byte) (count & 0xFF);

            md.reset();
            md.update(seed);
            md.update(counterBytes);
            byte[] hash = md.digest();

            int toCopy = Math.min(hLen, maskLen - generated);
            System.arraycopy(hash, 0, mask, generated, toCopy);
            generated += toCopy;
            count++;
        }
        return mask;
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

