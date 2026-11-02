package com.security.hsm.service;

import com.security.hsm.dto.ChangePinRequest;
import com.security.hsm.dto.ChangePinResponse;
import com.security.hsm.dto.PinPublicKeyResponse;
import com.security.hsm.dto.VerifyPinRequest;
import com.security.hsm.dto.VerifyPinResponse;
import com.security.hsm.service.hsm.HsmCryptoOperations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

/**
 * Servicio de Enrutamiento Ciego (Blind Routing) para el cambio de PIN transaccional.
 *
 * Responsabilidades:
 * 1. Exponer la llave pública RSA-2048 del HSM con soporte de caché (@Cacheable) para alta concurrencia en producción.
 * 2. Enrutar los criptogramas Base64 (encryptedCurrentPin y encryptedNewPin) hacia el HSM sin descifrarlos en la capa de aplicación.
 * 3. Retornar el nuevo PIN Block traducido bajo la llave maestra local (LMK) junto con metadatos de auditoría sin exponer datos sensibles.
 */
@Service
public class PinManagementService {

    private static final Logger log = LoggerFactory.getLogger(PinManagementService.class);

    private final HsmCryptoOperations hsmCryptoOperations;

    public PinManagementService(HsmCryptoOperations hsmCryptoOperations) {
        this.hsmCryptoOperations = hsmCryptoOperations;
    }

    /**
     * Obtiene la llave pública RSA-2048 del HSM (cacheada bajo 'hsmPinPublicKey').
     * En producción puede respaldarse con Redis/Caffeine sin tocar el código del servicio.
     */
    @Cacheable(value = "hsmPinPublicKey", key = "'activePinRsaKey'")
    public PinPublicKeyResponse getActivePinPublicKey() {
        log.debug("[BLIND-ROUTING] Consultando llave pública RSA activa desde el HSM...");
        return hsmCryptoOperations.getRsaPublicKey();
    }

    /**
     * Enruta de forma ciega la solicitud de cambio de PIN hacia el HSM.
     * En ningún punto del log ni de las variables de este servicio existe el PIN en texto plano.
     */
    public ChangePinResponse processBlindPinChange(ChangePinRequest request) {
        String transactionId = UUID.randomUUID().toString();
        String isoAccount12Digits = request.resolveIsoAccountNumber();

        log.info("[BLIND-ROUTING] Iniciando transacción de cambio de PIN txId={} para userId={}",
                transactionId, maskIdentifier(request.userId()));

        String newPinBlockUnderLmk = hsmCryptoOperations.translateAndChangePin(
                request.userId(),
                isoAccount12Digits,
                request.encryptedCurrentPin(),
                request.encryptedNewPin(),
                request.storedPinBlockUnderLmk()
        );

        log.info("[BLIND-ROUTING] Cambio de PIN completado exitosamente en HSM txId={} (KCV={})",
                transactionId, hsmCryptoOperations.getLmkKeyCheckValue());

        return new ChangePinResponse(
                transactionId,
                request.userId(),
                "PIN_CHANGED_SUCCESSFULLY",
                "ISO-9564-FORMAT-4",
                newPinBlockUnderLmk,
                hsmCryptoOperations.getLmkKeyCheckValue(),
                Instant.now()
        );
    }

    /**
     * Enruta de forma ciega la verificación del PIN de 4 dígitos hacia el HSM.
     */
    public VerifyPinResponse processBlindPinVerification(VerifyPinRequest request) {
        String transactionId = UUID.randomUUID().toString();
        String isoAccount12Digits = request.resolveIsoAccountNumber();

        log.info("[BLIND-ROUTING] Verificando PIN en HSM txId={} para userId={}",
                transactionId, maskIdentifier(request.userId()));

        boolean valid = hsmCryptoOperations.verifyPin(
                request.userId(),
                isoAccount12Digits,
                request.encryptedPin(),
                request.storedPinBlockUnderLmk()
        );

        return new VerifyPinResponse(
                transactionId,
                request.userId(),
                valid,
                "PIN_VERIFIED_SUCCESSFULLY",
                "ISO-9564-FORMAT-4",
                hsmCryptoOperations.getLmkKeyCheckValue(),
                Instant.now()
        );
    }

    private String maskIdentifier(String id) {
        if (id == null || id.length() <= 4) {
            return "****";
        }
        return "***" + id.substring(id.length() - 4);
    }
}

