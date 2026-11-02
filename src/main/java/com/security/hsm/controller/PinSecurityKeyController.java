package com.security.hsm.controller;

import com.security.hsm.dto.PinPublicKeyResponse;
import com.security.hsm.service.PinManagementService;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.TimeUnit;

/**
 * Endpoint de Llave Pública (GET /api/v1/security/pin-key).
 * Expone la llave pública RSA-2048 del HSM en formato X.509/PEM a las aplicaciones (Web/App)
 * o al backend principal, e incluye cabeceras Cache-Control además de la capa @Cacheable interna.
 */
@RestController
@RequestMapping("/api/v1/security")
@CrossOrigin(origins = "*")
public class PinSecurityKeyController {

    private final PinManagementService pinManagementService;

    public PinSecurityKeyController(PinManagementService pinManagementService) {
        this.pinManagementService = pinManagementService;
    }

    @GetMapping("/pin-key")
    public ResponseEntity<PinPublicKeyResponse> getPinPublicKey() {
        PinPublicKeyResponse response = pinManagementService.getActivePinPublicKey();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(15, TimeUnit.MINUTES).cachePublic())
                .body(response);
    }
}

