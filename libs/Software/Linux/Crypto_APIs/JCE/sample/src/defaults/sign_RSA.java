package defaults;

import CryptoServerJCE.*;

import java.security.*;
import java.security.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider for the
 * CryptoServer Hardware Security Module.
 * <p>
 * RSA signature creation / verification
 */
public class sign_RSA {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - sign_RSA ---\n");

        int[] sizes = {2048};
        Security.addProvider(new BouncyCastleProvider());
        Algorithm[] modes = buildRsaAlgorithms();

        CryptoServerProvider csProvider = null;

        try {
            // load provider, use the resources cfg file:
            csProvider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(sign_RSA.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            csProvider.loginPassword("JCE", "12345678");

            Security.addProvider(csProvider);

            // list of providers
            Provider[] provider = {csProvider, Security.getProvider("BC")};

            // for all combinations
            for (int ct = 0; ct <= 2; ct++) {
                System.out.println("\nSign on  : " + provider[ct & 1].getName());
                System.out.println("Verify on: " + provider[(ct >> 1) & 1].getName());

                // for all key sizes
                for (int size : sizes) {
                    System.out.println("  size: " + size);

                    // generate RSA key
                    KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA", provider[ct & 1]);
                    kg.initialize(size);
                    KeyPair keyPair = kg.generateKeyPair();
                    PrivateKey privateKey = keyPair.getPrivate();

                    // export public key
                    KeyFactory kf = KeyFactory.getInstance("RSA", provider[ct & 1]);
                    RSAPublicKeySpec publicKeySpec = kf.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);

                    // import public key into other provider
                    kf = KeyFactory.getInstance("RSA", provider[(ct >> 1) & 1]);
                    PublicKey publicKey = kf.generatePublic(publicKeySpec);

                    // for all modes
                    for (Algorithm mode : modes) {
                        String algo = mode.algo;

                        System.out.println("    algo: " + algo);

                        runSignVerifyTests(mode, algo, provider, ct, privateKey, publicKey);
                    }
                }
            }
        } catch (Exception ex) {
            throw ex;
        } finally {
            // logoff
            if (csProvider != null) {
                csProvider.close();
            }
        }

        System.out.println("Done");
    }

    private static Algorithm[] buildRsaAlgorithms() {
        return new Algorithm[]{
                new Algorithm("SHA1withRSA", null),
                new Algorithm("NONEwithRSA", null),
                new Algorithm("SHA224withRSA", null),
                new Algorithm("SHA256withRSA", null),
                new Algorithm("SHA384withRSA", null),
                new Algorithm("SHA512withRSA", null),
                new Algorithm("SHA3-224withRSA", null),
                new Algorithm("SHA3-256withRSA", null),
                new Algorithm("SHA3-384withRSA", null),
                new Algorithm("SHA3-512withRSA", null),
                new Algorithm("MD5withRSA", null),
                new Algorithm("RSASSA-PSS", PSSParameterSpec.DEFAULT),
                new Algorithm("RSASSA-PSS", null),
                new Algorithm("RSASSA-PSS", new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 32, 1)),
                new Algorithm("RSASSA-PSS", new PSSParameterSpec("SHA-224", "MGF1", MGF1ParameterSpec.SHA224, 32, 1)),
                new Algorithm("RSASSA-PSS", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)),
                new Algorithm("RSASSA-PSS", new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1)),
                new Algorithm("RSASSA-PSS", new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 20, 1)),
                new Algorithm("SHA512withRSASSA-PSS", null),
                new Algorithm("SHA512withRSASSA-PSS", new PSSParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1)),
                new Algorithm("SHA384withRSASSA-PSS", null),
                new Algorithm("SHA384withRSASSA-PSS", new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 38, 1)),
                new Algorithm("SHA256withRSASSA-PSS", null),
                new Algorithm("SHA256withRSASSA-PSS", new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)),
                new Algorithm("SHA224withRSASSA-PSS", null),
                new Algorithm("SHA224withRSASSA-PSS", new PSSParameterSpec("SHA-224", "MGF1", MGF1ParameterSpec.SHA224, 28, 1)),
                new Algorithm("SHA1withRSASSA-PSS", null),
                new Algorithm("SHA1withRSASSA-PSS", new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, 1)),
        };
    }

    private static void runSignVerifyTests(Algorithm mode, String algo, Provider[] provider, int ct, PrivateKey privateKey, PublicKey publicKey) throws Exception {
        // do test
        Signature sig = Signature.getInstance(algo, provider[ct & 1]);
        Signature ver = Signature.getInstance(algo, provider[(ct >> 1) & 1]);

        for (int len1 = 1; len1 < 33; len1 += 3) {
            byte[] data1 = getRandom(len1);

            for (int len2 = 1; len2 < 22; len2 += 2) {
                byte[] data2 = getRandom(len2);

                sig.initSign(privateKey);
                if (mode.param != null) {
                    sig.setParameter(mode.param);
                }

                sig.update(data1);
                sig.update(data2);
                byte[] sign = sig.sign();

                // verify
                byte[] data = cat(data1, data2);

                ver.initVerify(publicKey);
                if (mode.param != null) {
                    ver.setParameter(mode.param);
                }
                ver.update(data);
                if (!ver.verify(sign)) {
                    throw new Exception("Signature Verification failed");
                }
            }
        }
    }

    private static class Algorithm {
        String algo;
        AlgorithmParameterSpec param;

        public Algorithm(String algo, AlgorithmParameterSpec param) {
            this.algo = algo;
            this.param = param;
        }
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
