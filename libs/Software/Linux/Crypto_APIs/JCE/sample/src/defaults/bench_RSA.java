package defaults;
import CryptoServerJCE.*;
import java.util.*;
import java.security.*;
import javax.crypto.*;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 *
 * RSA benchmark
 *
 */
public class bench_RSA {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - bench_RSA ---\n");
        final byte[] data = "+++ data to be signed +++".getBytes();
        int[] keySizes = {1024, 2048, 4096};
        int loopCount = 1000;
        String keyName = "RSA Bench";

        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(bench_RSA.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            // load keystore
            KeyStore ks = loadKeystore(provider);

            for (int size : keySizes) {
                System.out.println("\nKey size: " + size);

                // Generate RSA key
                KeyPair keyPair = generateKeyPair(size, provider);
                PrivateKey prvKey = keyPair.getPrivate();
                PublicKey pubKey = keyPair.getPublic();

                prvKey = storeKey(ks, keyName, prvKey, provider);

                encryptData(provider, pubKey, data, loopCount, prvKey);

                signAndVerifyData(provider, loopCount, prvKey, data, pubKey);
            }
        } catch (Exception ex) {
            throw ex;
        } finally {
            closeProvider(provider);
        }

        System.out.println("Done");
    }

    private static void signAndVerifyData(CryptoServerProvider provider, int loopCount, PrivateKey prvKey, byte[] data, PublicKey pubKey) throws Exception {
        System.out.println("\n--- Signature benchmark ---");

        // sign data
        Signature s = Signature.getInstance("SHA1withRSA", provider);
        byte[] sig = null;

        Date start = new Date();

        sig = signData(loopCount, s, prvKey, data, sig);

        Date finish = new Date();
        printPerformance(finish, start, loopCount);

        // Verify Signature
        verifySignature(s, pubKey, data);
        if (!s.verify(sig)) {
            throw new Exception("Verification failed");
        }
    }

    private static void closeProvider(CryptoServerProvider provider) {
        // close
        if (provider != null) {
            provider.close();
        }
    }

    private static void verifySignature(Signature s, PublicKey pubKey, byte[] data) throws InvalidKeyException, SignatureException {
        s.initVerify(pubKey);
        s.update(data);
    }

    private static byte[] signData(int loopCount, Signature s, PrivateKey prvKey, byte[] data, byte[] sig) throws InvalidKeyException, SignatureException {
        for (int ct = 0; ct < loopCount; ct++) {
            s.initSign(prvKey);
            s.update(data);
            sig = s.sign();
        }
        return sig;
    }

    private static PrivateKey storeKey(KeyStore ks, String keyName, PrivateKey prvKey, CryptoServerProvider provider) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        // store key
        ks.setKeyEntry(keyName, prvKey, null, provider.getDumyCertificateChain());
        prvKey = (PrivateKey) ks.getKey(keyName, null);
        return prvKey;
    }

    private static void encryptData(CryptoServerProvider provider, PublicKey pubKey, byte[] data, int loopCount, PrivateKey prvKey) throws Exception {
        System.out.println("\n--- Encryption benchmark ---");

        // encrypt data
        Cipher c = Cipher.getInstance("RSA/None/NoPadding", provider);
        c.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] crypto = c.doFinal(data);
        byte[] plain = null;

        Date start = new Date();

        for (int ct = 0; ct < loopCount; ct++) {
            c.init(Cipher.DECRYPT_MODE, prvKey);
            plain = c.doFinal(crypto);
        }

        Date finish = new Date();

        if (!Arrays.equals(plain, data)) {
            throw new Exception("data compare failed");
        }
        printPerformance(finish, start, loopCount);
    }

    private static KeyStore loadKeystore(CryptoServerProvider provider) throws Exception {
        KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
        ks.load(null, null);
        return ks;
    }

    private static KeyPair generateKeyPair(int size, CryptoServerProvider provider) throws Exception {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA", provider);
        kg.initialize(size, null);
        return kg.generateKeyPair();
    }

    private static void printPerformance(Date finish, Date start, int loopCount) {
        long duration = finish.getTime() - start.getTime();
        long speed = loopCount * 1000L / duration;
        System.out.println("  Duration: " + duration + " ms");
        System.out.println("  Speed: " + speed + " op/second");
    }
}
