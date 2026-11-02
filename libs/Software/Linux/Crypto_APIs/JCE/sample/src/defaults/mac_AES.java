package defaults;

import CryptoServerJCE.*;
import CryptoServerAPI.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * Creation of message authentication code (MAC)
 */
public class mac_AES {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE : mac_AES ---\n");
        final byte[][] ivs = {{(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0},
                {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1}};

        String[] modes = {"AES", "AESwithPKCS5Padding"};

        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(mac_AES.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            // for all modes
            processMode(modes, provider, ivs);
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

    private static void processMode(String[] modes, CryptoServerProvider provider, byte[][] ivs) throws Exception {
        for (String mode : modes) {
            System.out.println("mode: " + mode);

            KeyGenerator kg = KeyGenerator.getInstance("AES", provider);
            kg.init(new CryptoServerKeyGenParameterSpec(256), null);
            SecretKey aesKey = kg.generateKey();

            // create data
            byte[] data1 = "We are ".getBytes();
            byte[] data2 = "what we were ".getBytes();
            byte[] data3 = "waiting for !".getBytes();

            if (!mode.contains("Padding")) {
                int len = data1.length + data2.length + data3.length;

                if ((len = len % 16) != 0) {
                    byte[] pad = new byte[16 - len];
                    Arrays.fill(pad, (byte) 0);
                    data3 = cat(data3, pad);
                }
            }

            byte[] data = cat(cat(data1, data2), data3);

            for (byte[] iv : ivs) {
                IvParameterSpec ivsp = new IvParameterSpec(iv);
                CryptoServerUtil.xtrace("iv", iv);

                // calculate MAC
                Mac mac = Mac.getInstance(mode, provider);
                mac.init(aesKey, ivsp);
                byte[] mac1 = mac.doFinal(data);

                CryptoServerUtil.xtrace("mac", mac1);

                // calculate MAC (demonstrate chunked operation)
                mac.init(aesKey, ivsp);
                mac.update(data1);
                mac.update(data2);
                mac.update(data3);
                byte[] mac2 = mac.doFinal();

                if (!Arrays.equals(mac1, mac2)) {
                    throw new Exception("Mac compare failed");
                }
            }
        }
    }
}
