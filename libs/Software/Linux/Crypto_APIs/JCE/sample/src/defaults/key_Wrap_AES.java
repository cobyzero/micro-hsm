package defaults;

import CryptoServerJCE.*;
import CryptoServerAPI.*;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.crypto.*;
import java.security.*;
import java.math.BigInteger;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * Export one key encrypted with another (AES) key
 */
public class key_Wrap_AES {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE: key_Wrap_AES ---\n");
        final String aesKeyName = "AES_imp_1";
        final byte[] testData = "Hello World".getBytes();

        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(key_Wrap_AES.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            // open key store
            KeyStore ks = openKeyStore(provider);

            // import AES key
            SecretKey aesKEK = importAesKey(provider, ks, aesKeyName);

            Cipher testCipher = Cipher.getInstance("DES/ECB/PKCS5Padding", provider);
            wrapUnwrapDesKey(provider, aesKEK, testCipher, testData);
            wrapUnwrapDesKeyWithGlobalExportPolicy(provider, aesKEK, testCipher, testData);

            Signature sig = Signature.getInstance("SHA1withRSA", provider);
            Signature ver = Signature.getInstance("SHA1withRSA", provider);
            wrapUnwrapRsaKey(provider, aesKEK, testData, sig, ver);
            wrapUnwrapRsaKeyWithGlobalExportPolicy(provider, aesKEK, sig, testData, ver);

            wrapUnwrapEcKey(provider, aesKEK, testData);
        } catch (Exception ex) {
            throw ex;
        } finally {
            // close
            closeProvider(provider);
        }

        System.out.println("Done");
    }

    private static void wrapUnwrapDesKey(CryptoServerProvider provider, SecretKey aesKEK, Cipher testCipher, byte[] testData) throws Exception {
        // ********************************************************************************
        // wrap / unwrap DES key with AES key
        // ********************************************************************************

        // generate DES key
        System.out.println("\ngenerate DES key...");

        CryptoServerKeyGenParameterSpec desParam = new CryptoServerKeyGenParameterSpec(168);
        desParam.setExportable(true);
        KeyGenerator kgDES = KeyGenerator.getInstance("DES", provider);
        kgDES.init(desParam, null);
        SecretKey desKey = kgDES.generateKey();

        // encrypt test data
        byte[] crypto = encryptTestData(testCipher, desKey, testData);

        // export (wrap) DES key (encrypted with AES key)
        System.out.println("export (wrap) DES key (encrypted with AES key)...");

        Cipher wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
        wrapCipher.init(Cipher.WRAP_MODE, aesKEK);
        byte[] keyBlob = wrapCipher.wrap(desKey);

        CryptoServerUtil.xtrace("key blob" + keyBlob.length, keyBlob);

        // import (unwrap) encrypted DES key
        desKey = unwrapSecretKey(wrapCipher, aesKEK, keyBlob);

        // decrypt test data
        byte[] plain = decryptTestData(testCipher, desKey, crypto);

        CryptoServerUtil.xtrace("decrypted test data", plain);

        // compare result
        compareResult(plain, testData);
    }

    private static void wrapUnwrapDesKeyWithGlobalExportPolicy(CryptoServerProvider provider, SecretKey aesKEK, Cipher testCipher, byte[] testData) throws Exception {
        SecretKey desKey;
        byte[] crypto;
        byte[] keyBlob;
        byte[] plain;
        Cipher wrapCipher;
        // ********************************************************************************
        // wrap / unwrap DES key with AES key (with global export policy)
        // ********************************************************************************

        desKey = generateDesKey(provider);

        // export (wrap) DES key (encrypted with AES key)
        System.out.println("export (wrap) DES key (encrypted with AES key)...");

        wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
        wrapCipher.init(Cipher.WRAP_MODE, aesKEK);
        keyBlob = wrapCipher.wrap(desKey);

        CryptoServerUtil.xtrace("key blob", keyBlob);

        desKey = unwrapSecretKey(wrapCipher, aesKEK, keyBlob);

        // encrypt test data
        crypto = encryptTestData(testCipher, desKey, testData);

        // decrypt test data
        plain = decryptTestData(testCipher, desKey, crypto);

        CryptoServerUtil.xtrace("decrypted test data", plain);

        // compare result
        compareResult(plain, testData);

        provider.setProperty("Export", "0"); // set global export policy to "DENY"
    }

    private static void wrapUnwrapRsaKey(CryptoServerProvider provider, SecretKey aesKEK, byte[] testData, Signature sig, Signature ver) throws Exception {
        Cipher wrapCipher;
        byte[] keyBlob;
        // ********************************************************************************
        // wrap / unwrap RSA key with AES key
        // ********************************************************************************

        KeyPair keyPair = generateRsaKey(provider);

        // export (wrap) RSA key (encrypted with AES key)
        System.out.println("export (wrap) RSA key (encrypted with AES key)...");

        wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
        wrapCipher.init(Cipher.WRAP_MODE, aesKEK);
        keyBlob = wrapCipher.wrap(keyPair.getPrivate());

        CryptoServerUtil.xtrace("key blob", keyBlob);

        // import (unwrap) encrypted RSA key
        System.out.println("import (unwrap) encrypted RSA key...");

        PrivateKey privateKey = unwrapPrivateKey(wrapCipher, aesKEK, "RSA", keyBlob);

        // sign test data
        byte[] signature = signTestData(sig, privateKey, testData);

        // verify test data
        verifyTestData(ver, keyPair, testData, signature);
    }

    private static void wrapUnwrapRsaKeyWithGlobalExportPolicy(CryptoServerProvider provider, SecretKey aesKEK, Signature sig, byte[] testData, Signature ver) throws Exception {
        PrivateKey privateKey;
        byte[] keyBlob;
        KeyPair keyPair;
        Cipher wrapCipher;
        byte[] signature;
        // ********************************************************************************
        // wrap / unwrap RSA key with AES key (with global export policy)
        // ********************************************************************************

        // generate RSA key
        System.out.println("\ngenerate RSA key...");

        provider.setProperty("Export", "1"); // set global export policy to "ALLOW"
        keyPair = generateRsaKey(provider);

        // export (wrap) RSA key (encrypted with AES key)
        System.out.println("export (wrap) RSA key (encrypted with AES key)...");

        wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
        wrapCipher.init(Cipher.WRAP_MODE, aesKEK);
        keyBlob = wrapCipher.wrap(keyPair.getPrivate());

        CryptoServerUtil.xtrace("key blob", keyBlob);

        privateKey = unwrapPrivateKey(wrapCipher, aesKEK, "RSA", keyBlob);

        // sign test data
        signature = signTestData(sig, privateKey, testData);

        // verify test data
        verifyTestData(ver, keyPair, testData, signature);

        provider.setProperty("Export", "0"); // set global export policy to "DENY"
    }

    private static void wrapUnwrapEcKey(CryptoServerProvider provider, SecretKey aesKEK, byte[] testData) throws Exception {
        byte[] keyBlob;
        Signature ver;
        Signature sig;
        byte[] signature;
        KeyPair keyPair;
        PrivateKey privateKey;
        Cipher wrapCipher;
        // ********************************************************************************
        // wrap / unwrap EC key with AES key
        // ********************************************************************************

        keyPair = generateEcKey(provider);

        // export (wrap) private EC key (encrypted with AES key)
        System.out.println("export (wrap) EC key (encrypted with AES key)...");

        wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
        wrapCipher.init(Cipher.WRAP_MODE, aesKEK);
        keyBlob = wrapCipher.wrap(keyPair.getPrivate());

        CryptoServerUtil.xtrace("key blob", keyBlob);

        // import (unwrap) encrypted EC key
        System.out.println("import (unwrap) encrypted EC key...");

        privateKey = unwrapPrivateKey(wrapCipher, aesKEK, "EC", keyBlob);

        // sign test data
        sig = Signature.getInstance("SHA512withECDSA", provider);
        signature = signTestData(sig, privateKey, testData);

        // verify test data
        ver = Signature.getInstance("SHA512withECDSA", provider);
        verifyTestData(ver, keyPair, testData, signature);
    }

    private static SecretKey generateDesKey(CryptoServerProvider provider) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // generate DES key
        System.out.println("\ngenerate DES key...");

        CryptoServerKeyGenParameterSpec desParam = new CryptoServerKeyGenParameterSpec(168);
        desParam.setExportable(true);
        KeyGenerator kgDES = KeyGenerator.getInstance("DES", provider);
        kgDES.init(desParam, null);
        return kgDES.generateKey();
    }

    private static KeyPair generateRsaKey(CryptoServerProvider provider) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // generate RSA key
        System.out.println("\ngenerate RSA key...");

        CryptoServerRSAKeyGenParameterSpec rsaParam = new CryptoServerRSAKeyGenParameterSpec(1024, new BigInteger("010001", 16));
        rsaParam.setExportable(true);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
        kpg.initialize(rsaParam, null);
        return kpg.generateKeyPair();
    }

    private static KeyPair generateEcKey(CryptoServerProvider provider) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        // generate EC key
        System.out.println("\ngenerate EC key...");

        CryptoServerECKeyGenParameterSpec ecParam = new CryptoServerECKeyGenParameterSpec("NIST-P384");
        ecParam.setExportable(true);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", provider);
        kpg.initialize(ecParam, null);
        return kpg.generateKeyPair();
    }

    private static void compareResult(byte[] plain, byte[] testData) throws Exception {
        if (!Arrays.equals(plain, testData)) {
            throw new Exception("En-/Decryption failed");
        }
    }

    private static void closeProvider(CryptoServerProvider provider) {
        if (provider != null) {
            provider.close();
        }
    }

    private static PrivateKey unwrapPrivateKey(Cipher wrapCipher, SecretKey aesKEK, String wrappedKeyAlgorithm, byte[] keyBlob) throws InvalidKeyException, NoSuchAlgorithmException {
        wrapCipher.init(Cipher.UNWRAP_MODE, aesKEK);
        return (PrivateKey) wrapCipher.unwrap(keyBlob, wrappedKeyAlgorithm, Cipher.PRIVATE_KEY);
    }

    private static SecretKey unwrapSecretKey(Cipher wrapCipher, SecretKey aesKEK, byte[] keyBlob) throws InvalidKeyException, NoSuchAlgorithmException {
        System.out.println("import (unwrap) encrypted DES key...");

        wrapCipher.init(Cipher.UNWRAP_MODE, aesKEK);
        return (SecretKey) wrapCipher.unwrap(keyBlob, "DES", Cipher.SECRET_KEY);
    }

    private static byte[] decryptTestData(Cipher testCipher, SecretKey desKey, byte[] crypto) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        testCipher.init(Cipher.DECRYPT_MODE, desKey);
        return testCipher.doFinal(crypto);
    }

    private static byte[] encryptTestData(Cipher testCipher, SecretKey desKey, byte[] testData) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        testCipher.init(Cipher.ENCRYPT_MODE, desKey);
        return testCipher.doFinal(testData);
    }

    private static void verifyTestData(Signature ver, KeyPair keyPair, byte[] testData, byte[] signature) throws Exception {
        System.out.println("verify signature...");

        ver.initVerify(keyPair.getPublic());
        ver.update(testData);

        if (!ver.verify(signature)) {
            throw new Exception("Signature verification failed");
        }
    }

    private static byte[] signTestData(Signature sig, PrivateKey privateKey, byte[] testData) throws InvalidKeyException, SignatureException {
        System.out.println("sign test data...");

        sig.initSign(privateKey);
        sig.update(testData);
        return sig.sign();
    }

    private static SecretKey importAesKey(CryptoServerProvider provider, KeyStore ks, String aesKeyName) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, KeyStoreException, UnrecoverableKeyException {
        KeyGenerator kgAES = KeyGenerator.getInstance("AES", provider);
        kgAES.init(new CryptoServerKeyGenParameterSpec(256), null);
        SecretKey aesKEK = kgAES.generateKey();

        ks.setKeyEntry(aesKeyName, aesKEK, null, null);
        return (SecretKey) ks.getKey(aesKeyName, null);
    }

    private static KeyStore openKeyStore(CryptoServerProvider provider) throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
        ks.load(null, null);
        return ks;
    }
}
