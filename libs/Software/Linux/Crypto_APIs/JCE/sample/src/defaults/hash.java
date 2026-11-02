package defaults;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import CryptoServerAPI.CryptoServerUtil;
import CryptoServerJCE.CryptoServerProvider;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider for the
 * CryptoServer Hardware Security Module.
 * <p>
 * Creation of hash
 */
public class hash {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE : hash ---\n");

        String[] modes = {"MD5", "SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512", "RMD-160", "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};

        CryptoServerProvider provCS = null;
        Provider provSun = null;

        try {
            // load provider
            provCS = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(hash.class.getResourceAsStream("/CryptoServer.cfg"));

            provSun = Security.getProvider("SUN");

            // authenticate
            provCS.loginPassword("JCE", "12345678");

            // create data
            byte[] data1 = "We are ".getBytes();
            byte[] data2 = "what we were ".getBytes();
            byte[] data3 = "waiting for !".getBytes();

            byte[] data = cat(cat(data1, data2), data3);

            runHashTests(modes, provCS, data, data1, data2, data3, provSun);
        } catch (Exception ex) {
            throw ex;
        } finally {
            closeProvider(provCS);
        }

        System.out.println("Done");
    }

    private static void runHashTests(String[] modes, CryptoServerProvider provCS, byte[] data, byte[] data1, byte[] data2, byte[] data3, Provider provSun) throws Exception {
        for (String mode : modes) {
            System.out.println("\nmode: " + mode + "\n");

            // calculate hash on CryptoServer
            MessageDigest hashCS = MessageDigest.getInstance(mode, provCS);

            byte[] hashCSSingle = hashCS.digest(data);

            CryptoServerUtil.xtrace("hash CS", hashCSSingle);

            hashCS.update(data1);
            hashCS.update(data2);
            hashCS.update(data3);

            byte[] hashCSMulti = hashCS.digest();

            if (!Arrays.equals(hashCSSingle, hashCSMulti)) {
                throw new Exception("Hash compare failed");
            }

            // calculate hash on SUN
            // SHA-224 and RMD-160 are not supported by the SUN provider
            if (mode.equals("SHA-224") || mode.equals("RMD-160") || mode.equals("SHA3-224") || mode.equals("SHA3-256") || mode.equals("SHA3-384") || mode.equals("SHA3-512")) {
                continue;
            }

            MessageDigest hashSun = MessageDigest.getInstance(mode, provSun);

            byte[] hashSunSingle = hashSun.digest(data);

            CryptoServerUtil.xtrace("hash Sun", hashSunSingle);

            hashSun.update(data1);
            hashSun.update(data2);
            hashSun.update(data3);

            byte[] hashSunMulti = hashSun.digest();

            // compare created hashes
            if (!Arrays.equals(hashSunSingle, hashSunMulti) || !Arrays.equals(hashCSSingle, hashSunSingle) || !Arrays.equals(hashCSMulti, hashSunMulti)) {
                throw new Exception("Hash compare failed");
            }
        }
    }

    private static void closeProvider(CryptoServerProvider provCS) {
        // logoff
        if (provCS != null) {
            provCS.close();
        }
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
