package defaults;

import CryptoServerJCE.*;

import java.security.*;
import java.security.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider for the
 * CryptoServer Hardware Security Module.
 * <p>
 * Elliptic Curve signature creation / verification
 */
public class sign_EC {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - sign_EC ---\n");

        String[] curves = {// brainpool curves
                "brainpoolP160r1", "brainpoolP256r1", "brainpoolP320r1", "brainpoolP384r1", "brainpoolP512r1", "brainpoolP160t1", "brainpoolP256t1", "brainpoolP320t1", "brainpoolP384t1", "brainpoolP512t1",
                // NIST curves (not available in Bouncy)
                // "NIST-P192", "NIST-P224", "NIST-P256", "NIST-P384", "NIST-P521",
                // binary curves
                "sect113r1", "sect233r1", "sect283r1", "sect409r1", "sect571r1", "sect163r2", "sect163k1", "sect233k1", "sect283k1", "sect409k1", "sect571k1",
                // prime curves
                "secp112r1", "secp128r1", "secp160r1", "secp112r2", "secp128r2", "secp160r2", "secp160k1", "secp192k1", "secp224k1", "secp256k1"};
        String[] modes = {
                "SHA1withECDSA",
                "SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA",
                "SHA3-224withECDSA", "SHA3-256withECDSA", "SHA3-384withECDSA", "SHA3-512withECDSA",
                // "MD5withECDSA", //(not available in Bouncy)
                "NONEwithECDSA"};

        CryptoServerProvider cryptoServerProvider = null;

        try {
            // load provider, use the resources cfg file:
            cryptoServerProvider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(sign_EC.class.getResourceAsStream("/CryptoServer.cfg"));
            // authenticate
            cryptoServerProvider.loginPassword("JCE", "12345678");

            Provider[] provider = setupSecurityProviders(cryptoServerProvider);

            for (int ct = 0; ct <= 2; ct++) {
                System.out.println("\nSign on  : " + provider[ct & 1].getName());
                System.out.println("Verify on: " + provider[(ct >> 1) & 1].getName());

                Provider provSign = provider[ct & 1];
                Provider provVerify = provider[(ct >> 1) & 1];

                // for all curves
                for (String curve : curves) {
                    System.out.println("curve: " + curve);
                    // generate EC key
                    KeyPair keyPair = generateKeyPair(curve, provider, ct);
                    PrivateKey privateKey = keyPair.getPrivate();

                    PublicKey publicKey = exportPublicKeyAndImportIntoOtherProvider(provider, ct, keyPair);

                    // for all algorithms
                    for (String algo : modes) {
                        testSignatureAlgorithm(algo, provSign, provVerify, privateKey, publicKey);
                    }
                }
            }

        } catch (Exception ex) {
            throw ex;
        } finally {
            // logoff
            if (cryptoServerProvider != null) {
                cryptoServerProvider.close();
            }
        }

        System.out.println("Done");
    }

    private static PublicKey exportPublicKeyAndImportIntoOtherProvider(Provider[] provider, int ct, KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // export public key
        KeyFactory kf = KeyFactory.getInstance("EC", provider[ct & 1]);
        ECPublicKeySpec publicKeySpec = kf.getKeySpec(keyPair.getPublic(), ECPublicKeySpec.class);

        // import public key into other provider
        kf = KeyFactory.getInstance("EC", provider[(ct >> 1) & 1]);
        return kf.generatePublic(publicKeySpec);
    }

    private static Provider[] setupSecurityProviders(CryptoServerProvider cryptoServerProvider) {
        Security.addProvider(new BouncyCastleProvider());
        Security.addProvider(cryptoServerProvider);

        return new Provider[]{cryptoServerProvider, Security.getProvider("BC")};
    }

    private static KeyPair generateKeyPair(String curve, Provider[] provider, int ct) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("EC", provider[ct & 1]);
        kg.initialize(new ECGenParameterSpec(curve));
        return kg.generateKeyPair();
    }

    private static byte[] getRandom(int length) {
        try {
            byte[] buf = new byte[length];
            SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");

            if (length > 0) {
                do {
                    rng.nextBytes(buf);
                } while (buf[0] == 0);
            }

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

    private static void testSignatureAlgorithm(String algo, Provider provSign, Provider provVerify, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        System.out.println("  algo: " + algo);

        // do test
        Signature sig = Signature.getInstance(algo, provSign);
        Signature ver = Signature.getInstance(algo, provVerify);

        for (int len1 = 1; len1 < 3; len1 += 3) {
            byte[] data1 = getRandom(algo.contains("NONE") ? 10 : len1);

            for (int len2 = 1; len2 < 22; len2 += 2) {
                byte[] data2 = getRandom(algo.contains("NONE") ? 10 : len2);

                byte[] data = cat(data1, data2);

                // sign
                sig.initSign(privateKey);
                sig.update(data1);
                sig.update(data2);
                byte[] sign = sig.sign();

                // verify
                ver.initVerify(publicKey);
                ver.update(data);
                if (!ver.verify(sign)) {
                    throw new Exception("Signature Verification failed");
                }
            }
        }
    }
}
