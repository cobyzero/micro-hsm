package defaults;

import java.security.*;

import CryptoServerJCE.CryptoServerProvider;

public class sign_DSA_P1363Format {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - sign_DSA_P1363Format ---\n");

        int size = 1024;
        String[] modes = { "SHA1withDSAinP1363Format", "SHA224withDSAinP1363Format", "SHA256withDSAinP1363Format", "NONEwithDSAinP1363Format" };

        CryptoServerProvider csProvider = null;

        try {
            // load provider, use the resources cfg file:
            csProvider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(sign_DSA_P1363Format.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            csProvider.loginPassword("JCE", "12345678");

            for (String algorithm : modes) {
                System.out.println("\nSign on : " + csProvider.getName());
                System.out.println("Verify on : " + csProvider.getName());

                KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA", csProvider);
                kg.initialize(size);
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
