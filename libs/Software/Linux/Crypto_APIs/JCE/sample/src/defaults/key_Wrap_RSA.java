package defaults;

import CryptoServerJCE.*;
import CryptoServerAPI.*;

import java.util.*;
import javax.crypto.*;
import java.security.*;
import java.math.BigInteger;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * Import / Export one key encrypted with another (RSA) key
 */
public class key_Wrap_RSA {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE: key_Wrap_RSA ---\n");
        final byte[] testData = "Hello World".getBytes();

        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(key_Wrap_RSA.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            // open key store
            KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
            ks.load(null, null);

            // import RSA key
            KeyPair keyPair = generateRsaKey(provider);

            // ********************************************************************************
            // wrap / unwrap AES key with RSA key
            // ********************************************************************************

            // generate AES key
            System.out.println("generate AES key...");

            KeyGenerator kg = KeyGenerator.getInstance("AES", provider);
            CryptoServerKeyGenParameterSpec aesParam = new CryptoServerKeyGenParameterSpec(256);
            aesParam.setPlainExportable(true);
            kg.init(aesParam, null);
            SecretKey aesKey = kg.generateKey();

            // encrypt data
            Cipher testCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", provider);
            testCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] crypto = testCipher.doFinal(testData);

            // export (wrap) AES key (encrypted with RSA key)
            System.out.println("export (wrap) AES key (encrypted with RSA key)...");

            Cipher wrapCipher = Cipher.getInstance("RSA/None/PKCS1Padding", provider);
            wrapCipher.init(Cipher.WRAP_MODE, keyPair.getPublic());
            byte[] keyBlob = wrapCipher.wrap(aesKey);

            CryptoServerUtil.xtrace("key blob", keyBlob);

            // import (unwrap) encrypted AES key
            System.out.println("import (unwrap) encrypted AES key...");

            wrapCipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate());
            aesKey = (SecretKey) wrapCipher.unwrap(keyBlob, "AES", Cipher.SECRET_KEY);

            // decrypt test data
            testCipher.init(Cipher.DECRYPT_MODE, aesKey);
            byte[] plain = testCipher.doFinal(crypto);

            CryptoServerUtil.xtrace("decrypted test data", plain);

            // compare result
            if (!Arrays.equals(plain, testData)) {
                throw new Exception("En-/Decryption failed");
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

    private static KeyPair generateRsaKey(CryptoServerProvider provider) throws Exception {
        CryptoServerRSAKeyGenParameterSpec rsaParam = new CryptoServerRSAKeyGenParameterSpec(1024, new BigInteger("010001", 16));
        rsaParam.setExportable(true);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
        kpg.initialize(rsaParam, null);
        return kpg.generateKeyPair();
    }
}
