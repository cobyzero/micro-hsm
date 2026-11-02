package com.security.hsm.controller;

import com.security.hsm.dto.ChangePinRequest;
import com.security.hsm.dto.ChangePinResponse;
import com.security.hsm.dto.VerifyPinRequest;
import com.security.hsm.dto.VerifyPinResponse;
import com.security.hsm.service.PinManagementService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Endpoint Transaccional de Cambio y Verificación de PIN (/api/v1/account/*).
 * Recibe userId y los bloques cifrados en Base64, enrutándolos de forma ciega
 * hacia el HSM sin que el backend conozca el PIN en texto plano.
 */
@RestController
@RequestMapping("/api/v1/account")
@CrossOrigin(origins = "*")
public class AccountPinController {

    private final PinManagementService pinManagementService;

    public AccountPinController(PinManagementService pinManagementService) {
        this.pinManagementService = pinManagementService;
    }

    @PostMapping("/change-pin")
    public ResponseEntity<ChangePinResponse> changePin(@Valid @RequestBody ChangePinRequest request) {
        ChangePinResponse response = pinManagementService.processBlindPinChange(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-pin")
    public ResponseEntity<VerifyPinResponse> verifyPin(@Valid @RequestBody VerifyPinRequest request) {
        VerifyPinResponse response = pinManagementService.processBlindPinVerification(request);
        return ResponseEntity.ok(response);
    }
}

