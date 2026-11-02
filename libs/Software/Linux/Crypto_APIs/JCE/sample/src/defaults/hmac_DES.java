package defaults;

import CryptoServerJCE.*;
import CryptoServerAPI.*;

import javax.crypto.*;
import java.util.Arrays;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * Creation of hash message authentication code (HMAC) with DES
 */
public class hmac_DES {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE : hmac_DES ---\n");
        int[] sizes = {56, 112, 168};

        String[] modes = {"HmacMD5", "HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512", "HmacRMD160", "HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384", "HmacSHA3-512"};

        CryptoServerProvider provCS = null;

        try {
            // load providers
            provCS = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(hmac_DES.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provCS.loginPassword("JCE", "12345678");

            for (int keySize : sizes) {
                System.out.println("Key size: " + keySize);
                String algorithm = (keySize == 56) ? "DES" : "DESede";

                // create key object
                KeyGenerator kg = KeyGenerator.getInstance(algorithm, provCS);
                kg.init(new CryptoServerKeyGenParameterSpec(keySize), null);
                SecretKey desKey = kg.generateKey();

                for (String mode : modes) {
                    System.out.println("\nmode: " + mode + "\n");

                    // create data
                    byte[] data1 = "We are ".getBytes();
                    byte[] data2 = "what we were ".getBytes();
                    byte[] data3 = "waiting for !".getBytes();

                    byte[] data = cat(cat(data1, data2), data3);

                    // calculate HMAC on CryptoServer
                    Mac hmacCS = Mac.getInstance(mode, provCS);

                    hmacCS.init(desKey);
                    byte[] hmac1CS = hmacCS.doFinal(data);

                    CryptoServerUtil.xtrace("hmac", hmac1CS);

                    // calculate HMAC (demonstrate chunked operation)
                    hmacCS.init(desKey);
                    hmacCS.update(data1);
                    hmacCS.update(data2);
                    hmacCS.update(data3);

                    if (!Arrays.equals(hmac1CS, hmacCS.doFinal())) {
                        throw new Exception("Hmac compare failed");
                    }
                }
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
