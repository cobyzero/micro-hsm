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
public class mac_DES {
    /**
     * main
     */
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE : mac_DES ---\n");

        final byte[][] ivs = {{(byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 0},
                {(byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1, (byte) 1}};

        String[] modes = {"DES", "DESwithPKCS5Padding"};

        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(mac_DES.class.getResourceAsStream("/CryptoServer.cfg"));

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

    private static SecretKey generateDesKey(CryptoServerProvider provider) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("DESede", provider);
        kg.init(new CryptoServerKeyGenParameterSpec(168), null);
        return kg.generateKey();
    }

    private static void processMode(String[] modes, CryptoServerProvider provider, byte[][] ivs) throws Exception {
        for (String mode : modes) {
            System.out.println("mode: " + mode);

            // create key object
            SecretKey desKey = generateDesKey(provider);

            // create data
            byte[] data1 = "0123456789".getBytes();
            byte[] data2 = "ABCDEFGHIJ".getBytes();

            if (!mode.contains("Padding")) {
                int len = data1.length + data2.length;

                if ((len = len % 8) != 0) {
                    byte[] pad = new byte[8 - len];
                    Arrays.fill(pad, (byte) 0);
                    data2 = cat(data2, pad);
                }
            }

            byte[] data = cat(data1, data2);

            for (byte[] iv : ivs) {
                IvParameterSpec ivsp = new IvParameterSpec(iv);
                CryptoServerUtil.xtrace("iv", iv);

                // calculate MAC
                Mac mac = Mac.getInstance(mode, provider);
                mac.init(desKey, ivsp);
                byte[] mac1 = mac.doFinal(data);

                CryptoServerUtil.xtrace("mac", mac1);

                // calculate MAC (demonstrate chunked operation)
                mac.init(desKey, ivsp);
                mac.update(data1);
                mac.update(data2);
                byte[] mac2 = mac.doFinal();

                if (!Arrays.equals(mac1, mac2)) {
                    throw new Exception("Mac compare failed");
                }
            }
        }
    }
}
