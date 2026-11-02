package defaults;

import java.security.*;
import java.security.spec.ECGenParameterSpec;

import CryptoServerJCE.CryptoServerProvider;

public class sign_ECDSA_P1363Format {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - sign_ECDSA_P1363Format ---\n");

        String curveName = "secp256k1";

        String[] modes = {"NONEwithECDSAinP1363Format", "SHA1withECDSAinP1363Format", "SHA224withECDSAinP1363Format", "SHA256withECDSAinP1363Format", "SHA384withECDSAinP1363Format", "SHA512withECDSAinP1363Format"};

        CryptoServerProvider csProvider = null;

        try {
            // load provider, use the resources cfg file:
            csProvider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(sign_ECDSA_P1363Format.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            csProvider.loginPassword("JCE", "12345678");

            for (String algorithm : modes) {
                System.out.println("\nSign on : " + csProvider.getName());
                System.out.println("Verify on : " + csProvider.getName());

                KeyPairGenerator kg = KeyPairGenerator.getInstance("EC", csProvider);
                kg.initialize(new ECGenParameterSpec(curveName));
                KeyPair keyPair = kg.generateKeyPair();
                PrivateKey privateKey = keyPair.getPrivate();

                Signature sig = Signature.getInstance(algorithm, csProvider);
                Signature ver = Signature.getInstance(algorithm, csProvider);

                byte[] data1 = null;
                data1 = getRandom(algorithm.contains("NONE") ? 20 : 64);

                sig.initSign(privateKey);
                sig.update(data1);
                byte[] sign = sig.sign();

                ver.initVerify(keyPair.getPublic());
                ver.update(data1);
                if (!ver.verify(sign)) {
                    throw new Exception("Signature " + algorithm + " Verification failed");
                } else {
                    System.out.println("Signature " + algorithm + " Verification SUCCESSFUL!!!");
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
}
