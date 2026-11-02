package com.security.hsm.crypto;

import com.security.hsm.exception.HsmErrorCode;
import com.security.hsm.exception.HsmOperationException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Set;

/**
 * Implementación del estándar financiero ISO 9564 (Formatos 0 y 4) para bloques de PIN.
 *
 * IMPORTANTE (PCI-PIN):
 * Esta clase se ejecuta EXCLUSIVAMENTE dentro de la frontera del adaptador HSM (Simulador o Enclave)
 * y en los tests de verificación. El microservicio en su capa de aplicación/controlador NUNCA
 * invoca ni conoce el PIN en claro.
 *
 * Todos los buffers intermedios (byte[] / char[]) se sobrescriben con ceros inmediatamente
 * en bloques try/finally para garantizar la volatilidad en memoria.
 */
public final class Iso9564PinBlockCodec {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of().withUpperCase();

    /**
     * Lista de PINs débiles o secuencias triviales rechazadas por políticas PCI-PIN opcionales.
     */
    private static final Set<String> WEAK_PINS = Set.of(
            "0000", "1111", "2222", "3333", "4444", "5555", "6666", "7777", "8888", "9999",
            "1234", "4321"
    );

    private Iso9564PinBlockCodec() {
    }

    /**
     * Construye un bloque ISO 9564 Formato 4 en claro (16 bytes / 32 caracteres hex)
     * o valida y extrae el PIN desde un bloque cifrado con RSA-OAEP enviado por el cliente.
     *
     * Estructura del Clear PIN Block ISO 9564 Formato 4 (32 hex chars = 16 bytes):
     * - Nibble 0: '4' (Control field para Formato 4)
     * - Nibble 1: '4' (Longitud del PIN: 4 dígitos)
     * - Nibbles 2..5: 4 dígitos del PIN (ej. "7392")
     * - Nibbles 6..15: 10 caracteres 'A' de relleno fijo (según ISO 9564-1 §9.4.2)
     * - Nibbles 16..31: 16 nibbles de relleno aleatorio o vinculación de PAN/Account (12 dígitos + pad)
     *
     * También soporta ISO 9564 Formato 0 (8 bytes / 16 hex chars) si la App envía un bloque compacto.
     */
    public static byte[] createClientFormat4Payload(char[] pin4Digits, String account12Digits) {
        validatePinDigits(pin4Digits);
        String normalizedAccount = normalizeAccount12Digits(account12Digits);

        // Construimos los 32 caracteres hexadecimales (16 bytes) del bloque en claro que el cliente
        // cifra con la llave pública RSA-OAEP (SHA-256).
        // Nibbles 0..15: "44" + PIN(4) + "AAAAAAAAAA"
        // Nibbles 16..31: "0000" + Account12Digits (vinculación criptográfica de cuenta dentro del sobre RSA)
        char[] hexChars = new char[32];
        try {
            hexChars[0] = '4';
            hexChars[1] = '4';
            System.arraycopy(pin4Digits, 0, hexChars, 2, 4);
            for (int i = 6; i < 16; i++) {
                hexChars[i] = 'A';
            }
            hexChars[16] = '0';
            hexChars[17] = '0';
            hexChars[18] = '0';
            hexChars[19] = '0';
            for (int i = 0; i < 12; i++) {
                hexChars[20 + i] = normalizedAccount.charAt(i);
            }
            return HEX.parseHex(new String(hexChars));
        } finally {
            Arrays.fill(hexChars, '\0');
        }
    }

    /**
     * Extrae y valida el PIN de 4 dígitos desde el bloque descifrado dentro del HSM,
     * verificando el formato ISO 9564 (Formato 4 de 16 bytes o Formato 0 de 8 bytes)
     * y el enlace con los 12 dígitos de la cuenta (PAN/Account binding).
     */
    public static char[] extractAndVerifyPinFromClientBlock(byte[] decryptedBlock, String expectedAccount12Digits) {
        if (decryptedBlock == null) {
            throw new HsmOperationException(HsmErrorCode.HSM_INVALID_PIN_BLOCK_FORMAT);
        }

        String normalizedAccount = normalizeAccount12Digits(expectedAccount12Digits);

        // Si el cliente envió 32 caracteres ASCII hexadecimales en lugar de 16 bytes binarios, lo normalizamos
        byte[] rawBytes = decryptedBlock;
        boolean convertedFromAscii = false;
        try {
            if (decryptedBlock.length == 32 && isAsciiHex(decryptedBlock)) {
                rawBytes = HEX.parseHex(new String(decryptedBlock));
                convertedFromAscii = true;
            }

            if (rawBytes.length == 16) {
                return parseFormat4Block(rawBytes, normalizedAccount);
            } else if (rawBytes.length == 8) {
                return parseFormat0Block(rawBytes, normalizedAccount);
            } else {
                throw new HsmOperationException(
                        HsmErrorCode.HSM_INVALID_PIN_BLOCK_FORMAT,
                        "Longitud de bloque inválida tras descifrado RSA: se esperaban 16 bytes (ISO Formato 4) u 8 bytes (ISO Formato 0)."
                );
            }
        } finally {
            if (convertedFromAscii) {
                zeroize(rawBytes);
            }
        }
    }

    private static char[] parseFormat4Block(byte[] block16Bytes, String expectedAccount12Digits) {
        String hex = HEX.formatHex(block16Bytes);
        // Nibble 0 = '4' (Format 4), Nibble 1 = '4' (PIN length 4)
        if (hex.charAt(0) != '4' || hex.charAt(1) != '4') {
            throw new HsmOperationException(
                    HsmErrorCode.HSM_INVALID_PIN_BLOCK_FORMAT,
                    "Cabecera de control ISO 9564 Formato 4 inválida (se esperaba '44')."
            );
        }

        // Nibbles 6..15 deben ser 'A'
        for (int i = 6; i < 16; i++) {
            if (hex.charAt(i) != 'A') {
                throw new HsmOperationException(
                        HsmErrorCode.HSM_INVALID_PIN_BLOCK_FORMAT,
                        "Padding ISO 9564 Formato 4 inválido en nibbles 6..15."
                );
            }
        }

        // Si los nibbles 16..19 son "0000", los nibbles 20..31 contienen el PAN/Account de 12 dígitos vinculado
        if (hex.startsWith("0000", 16)) {
            String embeddedAccount = hex.substring(20, 32);
            if (!embeddedAccount.equals(expectedAccount12Digits)) {
                throw new HsmOperationException(HsmErrorCode.HSM_PAN_BINDING_MISMATCH);
            }
        }

        char[] pin = new char[4];
        for (int i = 0; i < 4; i++) {
            char c = hex.charAt(2 + i);
            if (c < '0' || c > '9') {
                Arrays.fill(pin, '\0');
                throw new HsmOperationException(
                        HsmErrorCode.HSM_INVALID_PIN_BLOCK_FORMAT,
                        "El PIN extraído contiene caracteres no numéricos."
                );
            }
            pin[i] = c;
        }
        return pin;
    }

    private static char[] parseFormat0Block(byte[] block8Bytes, String expectedAccount12Digits) {
        byte[] panBlock = HEX.parseHex("0000" + expectedAccount12Digits);
        byte[] unxored = new byte[8];
        try {
            for (int i = 0; i < 8; i++) {
                unxored[i] = (byte) (block8Bytes[i] ^ panBlock[i]);
            }
            String hex = HEX.formatHex(unxored);
            if (hex.charAt(0) != '0' || hex.charAt(1) != '4' || !hex.substring(6).equals("FFFFFFFFFF")) {
                throw new HsmOperationException(
                        HsmErrorCode.HSM_INVALID_PIN_BLOCK_FORMAT,
                        "Estructura ISO 9564 Formato 0 inválida o PAN incorrecto."
                );
            }
            char[] pin = new char[4];
            for (int i = 0; i < 4; i++) {
                char c = hex.charAt(2 + i);
                if (c < '0' || c > '9') {
                    Arrays.fill(pin, '\0');
                    throw new HsmOperationException(HsmErrorCode.HSM_INVALID_PIN_BLOCK_FORMAT);
                }
                pin[i] = c;
            }
            return pin;
        } finally {
            zeroize(panBlock);
            zeroize(unxored);
        }
    }

    /**
     * Cifra un PIN de 4 dígitos bajo la llave maestra local (LMK AES-128) siguiendo
     * estrictamente el algoritmo de doble ronda de ISO 9564-1 Formato 4:
     *
     * 1. Bloque P (Plaintext PIN Field, 16 bytes):
     *    '4' | '4' | PIN(4) | 'AAAAAAAAAA' | Random(16 hex chars / 8 bytes)
     * 2. Bloque A (PAN / Account Field, 16 bytes):
     *    '0' (M=0 para 12 dígitos) | Account(12 dígitos) | '0000000000000000000' (19 ceros)
     * 3. Intermediate Block I = AES_Encrypt(K_LMK, P)
     * 4. Intermediate Block J = I XOR A
     * 5. Encrypted PIN Block E = AES_Encrypt(K_LMK, J)
     */
    public static String encryptIsoFormat4UnderLmk(char[] pin4Digits, String account12Digits, SecretKey lmkAesKey) {
        validatePinDigits(pin4Digits);
        String normalizedAccount = normalizeAccount12Digits(account12Digits);

        byte[] random8Bytes = new byte[8];
        SECURE_RANDOM.nextBytes(random8Bytes);
        String randomHex = HEX.formatHex(random8Bytes);

        byte[] plainPinField = null;
        byte[] panField = null;
        byte[] intermediateBlockA = null;
        byte[] xoredBlock = null;
        byte[] finalCipherBlock = null;

        try {
            String pinFieldHex = "44" + new String(pin4Digits) + "AAAAAAAAAA" + randomHex;
            String panFieldHex = "0" + normalizedAccount + "0000000000000000000";

            plainPinField = HEX.parseHex(pinFieldHex);
            panField = HEX.parseHex(panFieldHex);

            Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
            aesCipher.init(Cipher.ENCRYPT_MODE, lmkAesKey);

            // Ronda 1: AES_K(Plaintext PIN Field)
            intermediateBlockA = aesCipher.doFinal(plainPinField);

            // XOR con el PAN Field
            xoredBlock = new byte[16];
            for (int i = 0; i < 16; i++) {
                xoredBlock[i] = (byte) (intermediateBlockA[i] ^ panField[i]);
            }

            // Ronda 2: AES_K(Intermediate XOR PAN Field)
            finalCipherBlock = aesCipher.doFinal(xoredBlock);
            return HEX.formatHex(finalCipherBlock);
        } catch (HsmOperationException e) {
            throw e;
        } catch (Exception e) {
            throw new HsmOperationException(HsmErrorCode.HSM_INTERNAL_ERROR, e);
        } finally {
            zeroize(random8Bytes);
            zeroize(plainPinField);
            zeroize(panField);
            zeroize(intermediateBlockA);
            zeroize(xoredBlock);
            zeroize(finalCipherBlock);
        }
    }

    /**
     * Descifra un PIN Block ISO 9564 Formato 4 cifrado bajo la llave maestra local (LMK AES-128)
     * dentro del HSM para verificar el PIN actual contra el PIN almacenado en Base de Datos.
     */
    public static char[] decryptIsoFormat4UnderLmk(String encryptedPinBlockHex, String account12Digits, SecretKey lmkAesKey) {
        if (encryptedPinBlockHex == null || encryptedPinBlockHex.length() != 32) {
            throw new HsmOperationException(
                    HsmErrorCode.HSM_INVALID_PIN_BLOCK_FORMAT,
                    "El storedPinBlockUnderLmk debe ser un bloque hexadecimal de 32 caracteres (ISO 9564 Formato 4)."
            );
        }

        String normalizedAccount = normalizeAccount12Digits(account12Digits);
        byte[] cipherBytes = null;
        byte[] panField = null;
        byte[] xoredBlock = null;
        byte[] intermediateBlockA = null;
        byte[] plainPinField = null;

        try {
            cipherBytes = HEX.parseHex(encryptedPinBlockHex);
            panField = HEX.parseHex("0" + normalizedAccount + "0000000000000000000");

            Cipher aesCipher = Cipher.getInstance("AES/ECB/NoPadding");
            aesCipher.init(Cipher.DECRYPT_MODE, lmkAesKey);

            // Paso inverso 1: AES_Decrypt(K_LMK, E) -> J
            xoredBlock = aesCipher.doFinal(cipherBytes);

            // Paso inverso 2: I = J XOR A
            intermediateBlockA = new byte[16];
            for (int i = 0; i < 16; i++) {
                intermediateBlockA[i] = (byte) (xoredBlock[i] ^ panField[i]);
            }

            // Paso inverso 3: P = AES_Decrypt(K_LMK, I)
            plainPinField = aesCipher.doFinal(intermediateBlockA);
            String plainHex = HEX.formatHex(plainPinField);

            if (plainHex.charAt(0) != '4' || plainHex.charAt(1) != '4' || !plainHex.startsWith("AAAAAAAAAA", 6)) {
                throw new HsmOperationException(HsmErrorCode.HSM_PAN_BINDING_MISMATCH);
            }

            char[] pin = new char[4];
            for (int i = 0; i < 4; i++) {
                pin[i] = plainHex.charAt(2 + i);
            }
            return pin;
        } catch (HsmOperationException e) {
            throw e;
        } catch (Exception e) {
            throw new HsmOperationException(HsmErrorCode.HSM_INVALID_PIN_BLOCK_FORMAT, e);
        } finally {
            zeroize(cipherBytes);
            zeroize(panField);
            zeroize(xoredBlock);
            zeroize(intermediateBlockA);
            zeroize(plainPinField);
        }
    }

    public static void validatePinDigits(char[] pin) {
        if (pin == null || pin.length != 4) {
            throw new HsmOperationException(
                    HsmErrorCode.HSM_INVALID_PIN_BLOCK_FORMAT,
                    "El PIN debe tener exactamente 4 dígitos."
            );
        }
        for (char c : pin) {
            if (c < '0' || c > '9') {
                throw new HsmOperationException(
                        HsmErrorCode.HSM_INVALID_PIN_BLOCK_FORMAT,
                        "El PIN solo puede contener dígitos numéricos (0-9)."
                );
            }
        }
    }

    public static void enforceNewPinPolicy(char[] currentPin, char[] newPin) {
        if (Arrays.equals(currentPin, newPin)) {
            throw new HsmOperationException(HsmErrorCode.HSM_NEW_PIN_SAME_AS_CURRENT);
        }
        String newPinStr = new String(newPin);
        if (WEAK_PINS.contains(newPinStr)) {
            throw new HsmOperationException(HsmErrorCode.HSM_WEAK_PIN_REJECTED);
        }
    }

    public static String normalizeAccount12Digits(String account) {
        String digits = (account == null) ? "" : account.replaceAll("\\D", "");
        if (digits.length() >= 13) {
            return digits.substring(digits.length() - 13, digits.length() - 1);
        }
        if (digits.length() == 12) {
            return digits;
        }
        return String.format("%12s", digits).replace(' ', '0');
    }

    private static boolean isAsciiHex(byte[] bytes) {
        for (byte b : bytes) {
            boolean isDigit = (b >= '0' && b <= '9');
            boolean isUpperHex = (b >= 'A' && b <= 'F');
            boolean isLowerHex = (b >= 'a' && b <= 'f');
            if (!isDigit && !isUpperHex && !isLowerHex) {
                return false;
            }
        }
        return true;
    }

    public static void zeroize(byte[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, (byte) 0);
        }
    }

    public static void zeroize(char[] buffer) {
        if (buffer != null) {
            Arrays.fill(buffer, '\0');
        }
    }
}

