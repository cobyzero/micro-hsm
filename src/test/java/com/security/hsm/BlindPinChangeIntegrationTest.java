package com.security.hsm;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.hsm.crypto.Iso9564PinBlockCodec;
import com.security.hsm.dto.ApiErrorResponse;
import com.security.hsm.dto.ChangePinRequest;
import com.security.hsm.dto.ChangePinResponse;
import com.security.hsm.dto.PinPublicKeyResponse;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class BlindPinChangeIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static final String TEST_USER_ID = "usr-9876543210987";
    private static final String TEST_PAN = "4539123456789012"; // 16 digits PAN -> ISO 12 digits: 912345678901

    @Test
    @DisplayName("1. GET /api/v1/security/pin-key expone la llave pública RSA-2048 X.509/PEM con caché habilitado")
    void shouldExposeRsaPublicKeyInPemFormat() throws Exception {
        MvcResult result = mockMvc.perform(get("/api/v1/security/pin-key"))
                .andExpect(status().isOk())
                .andExpect(header().exists("Cache-Control"))
                .andExpect(jsonPath("$.keyId").value("utimaco-pin-rsa-2048-v1"))
                .andExpect(jsonPath("$.algorithm").value("RSA-OAEP-256"))
                .andExpect(jsonPath("$.pinBlockFormat").value("ISO-9564-FORMAT-4"))
                .andReturn();

        PinPublicKeyResponse keyResponse = objectMapper.readValue(
                result.getResponse().getContentAsString(), PinPublicKeyResponse.class
        );

        assertThat(keyResponse.publicKeyPem())
                .startsWith("-----BEGIN PUBLIC KEY-----")
                .endsWith("-----END PUBLIC KEY-----");
        assertThat(keyResponse.publicKeyBase64()).isNotBlank();
    }

    @Test
    @DisplayName("2. Flujo E2E completo de Cambio de PIN (Blind Routing): PIN inicial 1234 -> 7392 -> 8461")
    void shouldExecuteEndToEndBlindPinChangeSuccessfully() throws Exception {
        PublicKey hsmRsaPublicKey = fetchHsmPublicKey();
        String isoAccount12Digits = "912345678901"; // Derivado de TEST_PAN (4539123456789012)

        // Paso A: Primer cambio de PIN (del PIN inicial en simulador "1234" al nuevo PIN "7392")
        String encryptedCurrentPin1 = encryptClientPinBlock(new char[]{'1', '2', '3', '4'}, isoAccount12Digits, hsmRsaPublicKey);
        String encryptedNewPin1 = encryptClientPinBlock(new char[]{'7', '3', '9', '2'}, isoAccount12Digits, hsmRsaPublicKey);

        ChangePinRequest firstRequest = new ChangePinRequest(
                TEST_USER_ID,
                TEST_PAN,
                encryptedCurrentPin1,
                encryptedNewPin1,
                null
        );

        MvcResult firstResult = mockMvc.perform(post("/api/v1/account/change-pin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(firstRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PIN_CHANGED_SUCCESSFULLY"))
                .andExpect(jsonPath("$.pinBlockFormat").value("ISO-9564-FORMAT-4"))
                .andReturn();

        ChangePinResponse firstResponse = objectMapper.readValue(
                firstResult.getResponse().getContentAsString(), ChangePinResponse.class
        );

        // El HSM devuelve el nuevo PIN Block de 32 caracteres hexadecimales cifrado bajo LMK AES-128
        assertThat(firstResponse.newPinBlockUnderLmk()).hasSize(32).matches("^[0-9A-F]{32}$");
        assertThat(firstResponse.keyCheckValue()).hasSize(6);

        // Paso B: Segundo cambio de PIN enviando el storedPinBlockUnderLmk devuelto por el primer cambio ("7392" -> "8461")
        String encryptedCurrentPin2 = encryptClientPinBlock(new char[]{'7', '3', '9', '2'}, isoAccount12Digits, hsmRsaPublicKey);
        String encryptedNewPin2 = encryptClientPinBlock(new char[]{'8', '4', '6', '1'}, isoAccount12Digits, hsmRsaPublicKey);

        ChangePinRequest secondRequest = new ChangePinRequest(
                TEST_USER_ID,
                TEST_PAN,
                encryptedCurrentPin2,
                encryptedNewPin2,
                firstResponse.newPinBlockUnderLmk()
        );

        MvcResult secondResult = mockMvc.perform(post("/api/v1/account/change-pin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(secondRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PIN_CHANGED_SUCCESSFULLY"))
                .andReturn();

        ChangePinResponse secondResponse = objectMapper.readValue(
                secondResult.getResponse().getContentAsString(), ChangePinResponse.class
        );

        assertThat(secondResponse.newPinBlockUnderLmk())
                .hasSize(32)
                .isNotEqualTo(firstResponse.newPinBlockUnderLmk());

        // Paso C: Verificar con POST /api/v1/account/verify-pin que el nuevo PIN ("8461") es válido
        String encryptedVerifyPin = encryptClientPinBlock(new char[]{'8', '4', '6', '1'}, isoAccount12Digits, hsmRsaPublicKey);
        String verifyPayload = """
                {
                  "userId": "%s",
                  "panOrAccountNumber": "%s",
                  "encryptedPin": "%s",
                  "storedPinBlockUnderLmk": "%s"
                }
                """.formatted(TEST_USER_ID, TEST_PAN, encryptedVerifyPin, secondResponse.newPinBlockUnderLmk());

        mockMvc.perform(post("/api/v1/account/verify-pin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyPayload))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.status").value("PIN_VERIFIED_SUCCESSFULLY"));
    }

    @Test
    @DisplayName("3. Manejo de Errores: devuelve 422 HSM_ERR_01 cuando el PIN actual es incorrecto")
    void shouldRejectWhenCurrentPinDoesNotMatch() throws Exception {
        PublicKey hsmRsaPublicKey = fetchHsmPublicKey();
        String isoAccount12Digits = "912345678901";

        // Enviamos un PIN actual erróneo ("9999" en lugar del PIN registrado)
        String wrongCurrentPin = encryptClientPinBlock(new char[]{'9', '9', '9', '9'}, isoAccount12Digits, hsmRsaPublicKey);
        String validNewPin = encryptClientPinBlock(new char[]{'5', '8', '2', '0'}, isoAccount12Digits, hsmRsaPublicKey);

        ChangePinRequest request = new ChangePinRequest(
                "usr-mismatch-test",
                TEST_PAN,
                wrongCurrentPin,
                validNewPin,
                null
        );

        MvcResult result = mockMvc.perform(post("/api/v1/account/change-pin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath("$.errorCode").value("HSM_ERR_01"))
                .andReturn();

        ApiErrorResponse error = objectMapper.readValue(
                result.getResponse().getContentAsString(), ApiErrorResponse.class
        );
        assertThat(error.message()).contains("PIN actual ingresado es incorrecto");
    }

    @Test
    @DisplayName("4. Manejo de Errores: devuelve 400 HSM_ERR_02 cuando el formato de PIN Block no cumple ISO 9564")
    void shouldRejectMalformedPinBlockFormat() throws Exception {
        PublicKey hsmRsaPublicKey = fetchHsmPublicKey();

        // Ciframos con RSA-OAEP un bloque corrupto que no cumple ISO 9564
        byte[] malformedBlock = new byte[]{0x01, 0x02, 0x03, 0x04};
        String encryptedMalformed = encryptRawBytesWithRsaOaep(malformedBlock, hsmRsaPublicKey);

        ChangePinRequest request = new ChangePinRequest(
                "usr-malformed-test",
                TEST_PAN,
                encryptedMalformed,
                encryptedMalformed,
                null
        );

        mockMvc.perform(post("/api/v1/account/change-pin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("HSM_ERR_02"));
    }

    @Test
    @DisplayName("5. Manejo de Errores: devuelve 400 HSM_ERR_03 si el PAN del PIN Block no coincide con la cuenta")
    void shouldRejectWhenPanBindingInPinBlockDoesNotMatchAccount() throws Exception {
        PublicKey hsmRsaPublicKey = fetchHsmPublicKey();

        // El cliente arma el PIN Block con otra cuenta ("111111111111") distinta a TEST_PAN ("912345678901")
        String encryptedWithDifferentPan = encryptClientPinBlock(
                new char[]{'1', '2', '3', '4'}, "111111111111", hsmRsaPublicKey
        );
        String encryptedNew = encryptClientPinBlock(
                new char[]{'7', '3', '9', '2'}, "912345678901", hsmRsaPublicKey
        );

        ChangePinRequest request = new ChangePinRequest(
                "usr-pan-binding-test",
                TEST_PAN,
                encryptedWithDifferentPan,
                encryptedNew,
                null
        );

        mockMvc.perform(post("/api/v1/account/change-pin")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errorCode").value("HSM_ERR_03"));
    }

    private PublicKey fetchHsmPublicKey() throws Exception {
        MvcResult keyResult = mockMvc.perform(get("/api/v1/security/pin-key"))
                .andExpect(status().isOk())
                .andReturn();

        PinPublicKeyResponse keyResponse = objectMapper.readValue(
                keyResult.getResponse().getContentAsString(), PinPublicKeyResponse.class
        );

        byte[] derBytes = Base64.getDecoder().decode(keyResponse.publicKeyBase64());
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(derBytes));
    }

    private String encryptClientPinBlock(char[] pin4Digits, String isoAccount12Digits, PublicKey publicKey) throws Exception {
        byte[] clearBlock = Iso9564PinBlockCodec.createClientFormat4Payload(pin4Digits, isoAccount12Digits);
        try {
            return encryptRawBytesWithRsaOaep(clearBlock, publicKey);
        } finally {
            Iso9564PinBlockCodec.zeroize(clearBlock);
            Iso9564PinBlockCodec.zeroize(pin4Digits);
        }
    }

    private String encryptRawBytesWithRsaOaep(byte[] payload, PublicKey publicKey) throws Exception {
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
        );
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
        return Base64.getEncoder().encodeToString(rsaCipher.doFinal(payload));
    }
}
