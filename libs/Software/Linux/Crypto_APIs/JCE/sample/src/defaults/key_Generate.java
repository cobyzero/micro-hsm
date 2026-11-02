package defaults;

import CryptoServerJCE.*;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.*;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * Generate keys
 */
public class key_Generate {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE: key_Generate ---\n");
        final String desKeyName = "DES_gen_1";
        final String aesKeyName = "AES_gen_1";
        final String rsaPrivateKeyName = "{U}RSA_prv_gen_1";
        final String ecPrivateKeyName = "EC_prv_gen_1";
        final String dsaPrivateKeyName = "DSA_prv_gen_1";
        final String ecedPrivateKeyName = "ECEd_prv_gen_1";

        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(key_Generate.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            KeyStore ks = openKeyStore(provider);

            generateSymmetricKeys(provider, ks, aesKeyName, desKeyName);

            generateAsymmetricKeys(provider, ks, rsaPrivateKeyName, ecPrivateKeyName, dsaPrivateKeyName, ecedPrivateKeyName);

            // list keys
            Enumeration<String> kl = ks.aliases();

            System.out.println(String.format("%-12s %-20s %s", "type", "name", "creation date"));
            System.out.println("----------------------------------------------------------------------");

            while (kl.hasMoreElements()) {
                String name = kl.nextElement();
                Date date = ks.getCreationDate(name);
                String type;

                if (ks.isKeyEntry(name)) {
                    type = "Key";
                } else if (ks.isCertificateEntry(name)) {
                    type = "Certificate";
                } else {
                    type = "???";
                }

                System.out.println(String.format("%-12s %-20s %s", type, name, date));
            }
        } catch (Exception ex) {
            throw ex;
        } finally {
            // close
            if (provider != null) {
                provider.close();
            }
        }

        System.out.println("Done");
    }

    private static void generateAsymmetricKeys(CryptoServerProvider provider, KeyStore ks, String rsaPrivateKeyName, String ecPrivateKeyName, String dsaPrivateKeyName, String ecedPrivateKeyName) throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        // generate RSA key
        generateAndStoreKey("RSA", 2048, provider, ks, rsaPrivateKeyName);

        // generate ECDSA key
        generateAndStoreKey("EC", new ECGenParameterSpec("NIST-P256"), provider, ks, ecPrivateKeyName);

        // generate DSA key
        generateAndStoreKey("DSA", 1024, provider, ks, dsaPrivateKeyName);

        // generate EdDSA key
        generateAndStoreKey("EdDSA", new ECGenParameterSpec("Ed25519"), provider, ks, ecedPrivateKeyName);
    }

    private static void generateSymmetricKeys(CryptoServerProvider provider, KeyStore ks, String aesKeyName, String desKeyName) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException {
        // generate AES key
        System.out.println("generate AES key...");
        KeyGenerator kg = KeyGenerator.getInstance("AES", provider);
        CryptoServerKeyGenParameterSpec kgp = new CryptoServerKeyGenParameterSpec();
        kgp.setExportable(true);
        kgp.setKeySize(256);
        kg.init(kgp, null);
        SecretKey aesKey = kg.generateKey();
        ks.setKeyEntry(aesKeyName, aesKey, null, null);

        // generate DES key
        System.out.println("generate DES key...");
        kg = KeyGenerator.getInstance("DESede", provider);
        kg.init(112, null);
        SecretKey desKey = kg.generateKey();
        ks.setKeyEntry(desKeyName, desKey, null, null);
    }

    private static KeyStore openKeyStore(CryptoServerProvider provider) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        // open key store
        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
        ks.load(null, null);
        return ks;
    }

    private static void generateAndStoreKey(KeyPairGenerator kpg, CryptoServerProvider provider, KeyStore keyStore, String alias) throws KeyStoreException {
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        keyStore.setKeyEntry(alias, privateKey, null, provider.getDumyCertificateChain());
    }

    public static void generateAndStoreKey(String algorithm, int keySize, CryptoServerProvider provider, KeyStore keyStore, String alias) throws NoSuchAlgorithmException, KeyStoreException {
        System.out.println("generate " + algorithm + " key...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
        kpg.initialize(keySize);
        generateAndStoreKey(kpg, provider, keyStore, alias);
    }

    public static void generateAndStoreKey(String algorithm, AlgorithmParameterSpec paramSpec, CryptoServerProvider provider, KeyStore keyStore, String alias) throws NoSuchAlgorithmException, KeyStoreException, InvalidAlgorithmParameterException {
        System.out.println("generate " + algorithm + " key...");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithm, provider);
        kpg.initialize(paramSpec);
        generateAndStoreKey(kpg, provider, keyStore, alias);
    }
}
