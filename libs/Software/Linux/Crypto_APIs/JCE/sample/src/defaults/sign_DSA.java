package defaults;

import CryptoServerJCE.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.*;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * DSA signature creation / verification
 */
public class sign_DSA {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - sign_DSA ---\n");
        String PROV_SIGN;
        String[] modes;

        if (System.getProperty("os.name").contains("AIX")) {
            PROV_SIGN = "IBMJCE";

            modes = new String[]{"SHA1withDSA"};
        } else {
            PROV_SIGN = "BC";

            modes = new String[]{"SHA1withDSA",
                    // sha2
                    "SHA256withDSA", "SHA224withDSA", "SHA384withDSA", "SHA512withDSA",
                    // sha3
                    "SHA3-224withDSA", "SHA3-256withDSA", "SHA3-384withDSA", "SHA3-512withDSA",
                    "NONEwithDSA"};
        }

        int[] sizes = {1024};

        CryptoServerProvider csProvider = null;

        try {
            // load provider, use the resources cfg file:
            csProvider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(sign_DSA.class.getResourceAsStream("/CryptoServer.cfg"));

            Security.addProvider(csProvider);
            Security.addProvider(new BouncyCastleProvider());

            // authenticate
            csProvider.loginPassword("JCE", "12345678");

            runAllDsaTests(modes, csProvider, PROV_SIGN, sizes);
        } catch (Exception ex) {
            throw ex;
        } finally {
            // close
            if (csProvider != null) {
                csProvider.close();
            }
        }

        System.out.println("Done");
    }

    private static void runAllDsaTests(String[] modes, CryptoServerProvider csProvider, String PROV_SIGN, int[] sizes) throws Exception {
        Provider provSign;
        Provider provVerify;

        // for all combinations
        for (int ct = 0; ct < 2; ct++) {
            // for all algorithms
            for (String algo : modes) {
                System.out.println("algo: " + algo);

                if (ct == 0) {
                    provSign = csProvider;
                    provVerify = Security.getProvider(PROV_SIGN);
                } else {
                    provSign = Security.getProvider(PROV_SIGN);
                    provVerify = csProvider;
                }

                System.out.println("  Sign on  : " + provSign.getName());
                System.out.println("  Verify on: " + provVerify.getName());

                // for all key sizes
                for (int size : sizes) {
                    System.out.println("    size: " + size);

                    KeyPair keyPair = generateDsaKeyPair(size, provSign);
                    PrivateKey privateKey = keyPair.getPrivate();

                    PublicKey publicKey = exportPublicKeyAndImportIntoOtherProvider(provSign, keyPair, provVerify);

                    runSignVerifyTests(algo, provSign, provVerify, privateKey, publicKey);
                }
            }
        }
    }

    private static void runSignVerifyTests(String algo, Provider provSign, Provider provVerify, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        // do test
        Signature sig = Signature.getInstance(algo, provSign);
        Signature ver = Signature.getInstance(algo, provVerify);

        for (int len1 = 1; len1 < 33; len1 += 3) {
            byte[] data1 = getRandom(algo.contains("NONE") ? 10 : len1);

            for (int len2 = 1; len2 < 22; len2 += 2) {
                byte[] data2 = getRandom(algo.contains("NONE") ? 10 : len2);

                // sign
                sig.initSign(privateKey);
                sig.update(data1);
                sig.update(data2);
                byte[] sign = sig.sign();

                // verify
                byte[] data = cat(data1, data2);

                ver.initVerify(publicKey);
                ver.update(data);
                if (!ver.verify(sign)) {
                    throw new Exception("Signature Verification failed");
                }
            }
        }
    }

    private static PublicKey exportPublicKeyAndImportIntoOtherProvider(Provider provSign, KeyPair keyPair, Provider provVerify) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // export public key
        KeyFactory kf = KeyFactory.getInstance("DSA", provSign);
        DSAPublicKeySpec publicKeySpec = kf.getKeySpec(keyPair.getPublic(), DSAPublicKeySpec.class);

        // import public key into other provider
        kf = KeyFactory.getInstance("DSA", provVerify);
        return kf.generatePublic(publicKeySpec);
    }

    private static KeyPair generateDsaKeyPair(int size, Provider provSign) throws NoSuchAlgorithmException {
        // generate DSA key
        KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA", provSign);
        kg.initialize(size);
        return kg.generateKeyPair();
    }

    private static byte[] getRandom(int length) {
        try {
            byte[] buf = new byte[length];
            SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");

            do {
                rng.nextBytes(buf);
            } while (buf[0] == 0);

            return buf;
        } catch (Exception ex) {
            return null;
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
