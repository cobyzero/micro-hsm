package defaults;

import CryptoServerJCE.*;
import CryptoServerAPI.*;

import javax.crypto.*;

import java.security.*;
import java.util.Arrays;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * Creation of hash message authentication code (HMAC) with AES
 */
public class hmac_AES {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE : hmac_AES ---\n");
        int[] sizes = {128, 192, 256};

        String[] modes = {"HmacMD5", "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512", "HmacRMD160", "HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384", "HmacSHA3-512"};

        CryptoServerProvider provCS = null;
        Provider provSun = null;

        try {
            // load providers
            provCS = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(hmac_AES.class.getResourceAsStream("/CryptoServer.cfg"));
            provSun = Security.getProvider("SunJCE");

            // authenticate
            provCS.loginPassword("JCE", "12345678");

            for (int keySize : sizes) {
                System.out.println("Key size: " + keySize);

                SecretKey aesKey = generateAesKey(keySize, provSun);

                runHmacTests(modes, provCS, aesKey, provSun);
            }
        } catch (Exception ex) {
            throw ex;
        } finally {
            // close
            if (provCS != null) {
                provCS.close();
            }
        }

        System.out.println("Done");
    }

    private static void runHmacTests(String[] modes, CryptoServerProvider provCS, SecretKey aesKey, Provider provSun) throws Exception {
        for (String mode : modes) {
            System.out.println("\nmode: " + mode + "\n");

            // create data
            byte[] data1 = "We are ".getBytes();
            byte[] data2 = "what we were ".getBytes();
            byte[] data3 = "waiting for !".getBytes();

            byte[] data = cat(cat(data1, data2), data3);

            // calculate HMAC on CryptoServer
            byte[] hmacCS = computeAndCheckHmac("hmac CS", mode, provCS, aesKey, data, data1, data2, data3);

            // calculate HMAC on SunJCE

            // SHA224 and RMD160 are not supported by the SunJCE provider
            if (mode.equals("HmacSHA224") || mode.equals("HmacRMD160") || mode.equals("HmacSHA3-224") || mode.equals("HmacSHA3-256") || mode.equals("HmacSHA3-384") || mode.equals("HmacSHA3-512")) {
                continue;
            }
            byte[] hmacSun = computeAndCheckHmac("hmac SunJCE", mode, provSun, aesKey, data, data1, data2, data3);

            if (!Arrays.equals(hmacCS, hmacSun)) {
                throw new Exception("Hmac compare failed");
            }
        }
    }

    private static byte[] computeAndCheckHmac(String label, String mode, Provider provider, SecretKey key, byte[] data, byte[] data1, byte[] data2, byte[] data3) throws Exception {
        Mac mac = Mac.getInstance(mode, provider);
        mac.init(key);
        byte[] fullHmac = mac.doFinal(data);
        CryptoServerUtil.xtrace(label, fullHmac);
        // calculate HMAC (demonstrate chunked operation)
        mac.init(key);
        mac.update(data1);
        mac.update(data2);
        mac.update(data3);
        byte[] chunkedHmac = mac.doFinal();
        // compare created Hmacs
        if (!Arrays.equals(fullHmac, chunkedHmac)) {
            throw new Exception("Hmac compare failed");
        }
        return fullHmac;
    }

    private static SecretKey generateAesKey(int keySize, Provider provSun) throws NoSuchAlgorithmException {
        // create key object
        KeyGenerator kg = KeyGenerator.getInstance("AES", provSun);
        kg.init(keySize);
        return kg.generateKey();
    }

    private static byte[] cat(byte[] a, byte[] b) {
        if (a == null) {
            return (b);
        }
        if (b == null) {
            return (a);
        }

        byte[] res = new byte[a.length + b.length];
        System.arraycopy(a, 0, res, 0, a.length);
        System.arraycopy(b, 0, res, a.length, b.length);

        return (res);
    }
}
