package com.security.hsm.service.hsm;

import com.security.hsm.config.HsmProperties;
import com.security.hsm.exception.HsmErrorCode;
import com.security.hsm.exception.HsmOperationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Adaptador nativo PKCS#11 / JCE para conectarse al contenedor Docker del Simulador Utimaco
 * o al HSM físico Utimaco PaymentServer en producción mediante el driver libcs_pkcs11_R3.so.
 *
 * Se activa automáticamente cuando:
 *   hsm.mode=PKCS11 (o variable de entorno HSM_MODE=PKCS11)
 *
 * Configuración en Producción vía Variables de Entorno (Cero Refactorización):
 *   - HSM_MODE=PKCS11
 *   - HSM_DEVICE=3001@10.20.30.40
 *   - HSM_SLOT_ID=0
 *   - HSM_CRYPTO_OFFICER_PIN=<PIN_CO_PRODUCCION>
 *   - HSM_PKCS11_LIBRARY=/usr/lib/utimaco/libcs_pkcs11_R3.so
 *   - HSM_RSA_KEY_ALIAS=PIN_E2E_RSA_2048
 *   - HSM_LMK_KEY_ALIAS=LMK_PIN_AES_128
 */
@Component
public class Pkcs11UtimacoHsmAdapter extends AbstractJceHsmAdapter {

    private static final Logger log = LoggerFactory.getLogger(Pkcs11UtimacoHsmAdapter.class);

    private final String providerName;
    private final PublicKey rsaPublicKey;
    private final PrivateKey rsaPrivateKey;
    private final SecretKey lmkAesKey;

    public Pkcs11UtimacoHsmAdapter(HsmProperties properties) {
        super(properties);
        try {
            log.info("[UTIMACO-PKCS11] Conectando a Utimaco PaymentServer (Library={}, Slot={}, Device={})...",
                    properties.getPkcs11Library(), properties.getSlotId(), properties.getDevice());

            // Configuración inline SunPKCS11 compatible con Java 21 (Provider.configure)
            String pkcs11InlineConfig = String.format(
                    "--name = UtimacoPaymentHSM\n" +
                    "library = %s\n" +
                    "slot = %d\n",
                    properties.getPkcs11Library(),
                    properties.getSlotId()
            );

            Provider basePkcs11Provider = Security.getProvider("SunPKCS11");
            if (basePkcs11Provider == null) {
                throw new HsmOperationException(
                        HsmErrorCode.HSM_COMMUNICATION_ERROR,
                        "El proveedor SunPKCS11 no está disponible en este runtime de Java 21."
                );
            }

            Provider utimacoProvider = basePkcs11Provider.configure(pkcs11InlineConfig);
            Security.addProvider(utimacoProvider);
            this.providerName = utimacoProvider.getName();

            char[] coPinChars = properties.getCryptoOfficerPin().toCharArray();
            KeyStore pkcs11KeyStore = KeyStore.getInstance("PKCS11", utimacoProvider);
            pkcs11KeyStore.load(null, coPinChars);

            // Cargar manejadores (handles opacos) de la llave privada/pública RSA y de la LMK AES
            this.rsaPrivateKey = (PrivateKey) pkcs11KeyStore.getKey(properties.getRsaKeyAlias(), coPinChars);
            this.rsaPublicKey = resolvePublicKeyFromHsmOrExport(pkcs11KeyStore, properties.getRsaKeyAlias(), this.rsaPrivateKey);
            this.lmkAesKey = (SecretKey) pkcs11KeyStore.getKey(properties.getLmkKeyAlias(), coPinChars);

            if (this.rsaPrivateKey == null || this.lmkAesKey == null) {
                throw new HsmOperationException(
                        HsmErrorCode.HSM_COMMUNICATION_ERROR,
                        "No se encontraron las llaves requeridas en el Slot PKCS#11 (" +
                                properties.getRsaKeyAlias() + " / " + properties.getLmkKeyAlias() + ")."
                );
            }

            log.info("[UTIMACO-PKCS11] Sesión PKCS#11 establecida exitosamente con proveedor '{}'.", this.providerName);
        } catch (HsmOperationException e) {
            throw e;
        } catch (Exception e) {
            throw new HsmOperationException(HsmErrorCode.HSM_COMMUNICATION_ERROR, e);
        }
    }

    @Override
    protected PublicKey resolveRsaPublicKey() {
        return rsaPublicKey;
    }

    @Override
    protected PrivateKey resolveRsaPrivateKey() {
        return rsaPrivateKey;
    }

    @Override
    protected SecretKey resolveLmkAesKey() {
        return lmkAesKey;
    }

    @Override
    protected String getJceProviderName() {
        return providerName;
    }

    /**
     * Resuelve la llave pública RSA desde el certificado en el Slot PKCS#11, desde el archivo PEM exportado,
     * o a partir del módulo público del manejador RSA en el HSM (exponent 65537).
     */
    private PublicKey resolvePublicKeyFromHsmOrExport(KeyStore keyStore, String alias, PrivateKey privateKey) throws Exception {
        Certificate cert = keyStore.getCertificate(alias);
        if (cert != null) {
            return cert.getPublicKey();
        }

        Path exportedPem = Path.of("/exported-keys/pin_e2e_rsa_pub.pem");
        if (Files.exists(exportedPem)) {
            String pem = Files.readString(exportedPem)
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] der = Base64.getDecoder().decode(pem);
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(der));
        }

        if (privateKey instanceof RSAPrivateCrtKey crtKey) {
            return KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(crtKey.getModulus(), crtKey.getPublicExponent())
            );
        }
        if (privateKey instanceof RSAPrivateKey rsaPriv) {
            return KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(rsaPriv.getModulus(), BigInteger.valueOf(65537))
            );
        }

        throw new HsmOperationException(
                HsmErrorCode.HSM_COMMUNICATION_ERROR,
                "No fue posible resolver la llave pública RSA para el alias: " + alias
        );
    }
}

