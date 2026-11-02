package com.security.hsm.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propiedades de conexión hacia el Utimaco PaymentServer HSM (o Simulador).
 * Diseñado para que el pase a producción requiera cero refactorización de código,
 * actualizando únicamente las variables de entorno (HSM_MODE, HSM_DEVICE, HSM_SLOT_ID, HSM_CRYPTO_OFFICER_PIN).
 */
@ConfigurationProperties(prefix = "hsm")
public class HsmProperties {

    public enum Mode {
        /**
         * Conexión nativa PKCS#11 (SunPKCS11 / libcs_pkcs11_R3.so) contra el contenedor
         * Docker del Simulador Utimaco o el appliance físico Utimaco PaymentServer.
         */
        PKCS11
    }

    /**
     * Modo de operación obligatorio: PKCS11 (conectado al HSM Utimaco).
     */
    private Mode mode = Mode.PKCS11;

    /**
     * Host o IP del Utimaco PaymentServer (ej. 10.20.30.40 o utimaco-sim).
     */
    private String host = "127.0.0.1";

    /**
     * Puerto TCP del Utimaco PaymentServer (por defecto 3001).
     */
    private int port = 3001;

    /**
     * Cadena de dispositivo Utimaco en formato Puerto@IP (ej. 3001@127.0.0.1).
     */
    private String device = "3001@127.0.0.1";

    /**
     * Slot ID del HSM donde residen las llaves transaccionales.
     */
    private int slotId = 0;

    /**
     * PIN del Crypto Officer (CO) del Slot en el HSM.
     */
    private String cryptoOfficerPin = "123456";

    /**
     * Ruta al binario nativo PKCS#11 de Utimaco (ej. /usr/lib/utimaco/libcs_pkcs11_R3.so).
     */
    private String pkcs11Library = "/usr/lib/utimaco/libcs_pkcs11_R3.so";

    /**
     * Ruta al archivo cs_pkcs11_R3.cfg de Utimaco.
     */
    private String pkcs11ConfigPath = "/etc/utimaco/cs_pkcs11_R3.cfg";

    /**
     * Alias / Label del par de llaves asimétricas RSA-2048 dentro del HSM.
     */
    private String rsaKeyAlias = "PIN_E2E_RSA_2048";

    /**
     * Alias / Label de la llave maestra local (LMK / ZPK AES-128) dentro del HSM.
     */
    private String lmkKeyAlias = "LMK_PIN_AES_128";

    /**
     * Identificador de versión de llave pública expuesto a los clientes Web/App.
     */
    private String keyId = "utimaco-pin-rsa-2048-v1";

    public Mode getMode() {
        return mode;
    }

    public void setMode(Mode mode) {
        this.mode = mode;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getDevice() {
        return device;
    }

    public void setDevice(String device) {
        this.device = device;
    }

    public int getSlotId() {
        return slotId;
    }

    public void setSlotId(int slotId) {
        this.slotId = slotId;
    }

    public String getCryptoOfficerPin() {
        return cryptoOfficerPin;
    }

    public void setCryptoOfficerPin(String cryptoOfficerPin) {
        this.cryptoOfficerPin = cryptoOfficerPin;
    }

    public String getPkcs11Library() {
        return pkcs11Library;
    }

    public void setPkcs11Library(String pkcs11Library) {
        this.pkcs11Library = pkcs11Library;
    }

    public String getPkcs11ConfigPath() {
        return pkcs11ConfigPath;
    }

    public void setPkcs11ConfigPath(String pkcs11ConfigPath) {
        this.pkcs11ConfigPath = pkcs11ConfigPath;
    }

    public String getRsaKeyAlias() {
        return rsaKeyAlias;
    }

    public void setRsaKeyAlias(String rsaKeyAlias) {
        this.rsaKeyAlias = rsaKeyAlias;
    }

    public String getLmkKeyAlias() {
        return lmkKeyAlias;
    }

    public void setLmkKeyAlias(String lmkKeyAlias) {
        this.lmkKeyAlias = lmkKeyAlias;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }
}

