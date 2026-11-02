package defaults;
import CryptoServerJCE.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 *
 * RSA encryption / decryption
 *
 */
public class crypt_RSA {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - crypt_RSA ---\n");
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        int[] sizes = new int[] {1024, 1536, 2048};

        Algorithm[] modes = buildModes();

        CryptoServerProvider csProvider = null;

        try {
            // load provider
            csProvider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(crypt_RSA.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            csProvider.loginPassword("JCE", "12345678");

            Provider[] provider = {csProvider, Security.getProvider("BC")};

            runAllEncryptDecryptTests(provider, sizes, modes);

            System.out.println("NO ERRORS!!!!");
        } catch (Exception ex) {
            throw ex;
        } finally {
            closeProvider(csProvider);
        }

        System.out.println("Done");
    }

    private static void runAllEncryptDecryptTests(Provider[] provider, int[] sizes, Algorithm[] modes) throws Exception {
        for (int ct = 0; ct <= 2; ct++) {
            System.out.println("\nEncrypt on  : " + provider[ct & 1].getName());
            System.out.println("Decrypt on : " + provider[(ct >> 1) & 1].getName());

            for (int size : sizes) {
                System.out.println("  size: " + size);

                KeyPair keyPair = generateKeyPair(size, provider, ct);
                PrivateKey privateKey = keyPair.getPrivate();

                PublicKey publicKey = exportPublicKeyAndImportIntoOtherProvider(provider, ct, keyPair);

                runCipherModeTests(provider, modes, size, ct, publicKey, privateKey);
            }

            System.out.println("#####################################################################");
        }
    }

    private static void runCipherModeTests(Provider[] provider, Algorithm[] modes, int size, int ct, PublicKey publicKey, PrivateKey privateKey) throws Exception {
        for (Algorithm mode : modes) {
            System.out.println("Cipher algorithm : " + mode.algo);

            Cipher enc = Cipher.getInstance(mode.algo, provider[ct & 1]);
            Cipher dec = Cipher.getInstance(mode.algo, provider[(ct >> 1) & 1]);

            for (int len1 = 1; len1 < 32; len1++) {
                byte[] data1 = getRandom(len1);

                for (int len2 = 1; len2 < 11; len2++) {
                    byte[] data2 = getRandom(len2);

                    enc.init(Cipher.ENCRYPT_MODE, publicKey, mode.param);
                    dec.init(Cipher.DECRYPT_MODE, privateKey, mode.param);

                    // encrypt
                    enc.update(data1);
                    byte[] crypto = enc.doFinal(data2);

                    // decrypt
                    byte[] plain = strip(dec.doFinal(crypto));

                    // compare
                    byte[] data = cat(data1, data2);

                    if (!Arrays.equals(data, plain)) {
                        System.out.println("Keysize=" + size + ", mode=" + mode.algo + ", len=" + len1 + "-" + len2);
                        throw new Exception("En-/Decryption failed");
                    }
                }
            }
        }
    }

    private static void closeProvider(CryptoServerProvider csProvider) {
        // close
        if (csProvider != null) {
            csProvider.close();
        }
    }

    private static Algorithm[] buildModes() {
        return new Algorithm[]{new Algorithm("RSA/ECB/NoPadding", null), new Algorithm("RSA/ECB/PKCS1Padding", null),
                new Algorithm("RSA/ECB/OAEPPadding", new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, new PSource.PSpecified("Utimaco".getBytes()))),
                new Algorithm("RSA/ECB/OAEPPadding", new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, new PSource.PSpecified("Sophos".getBytes()))),
                new Algorithm("RSA/ECB/OAEPPadding", new OAEPParameterSpec("SHA3-256", "MGF1", MGF1ParameterSpec.SHA1, new PSource.PSpecified("Sophos".getBytes())))};
    }

    private static PublicKey exportPublicKeyAndImportIntoOtherProvider(Provider[] provider, int ct, KeyPair keyPair) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // export public key
        KeyFactory kf = KeyFactory.getInstance("RSA", provider[(ct >> 1) & 1]);
        RSAPublicKeySpec publicKeySpec = kf.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);

        // import public key into other provider
        kf = KeyFactory.getInstance("RSA", provider[ct & 1]);
        return kf.generatePublic(publicKeySpec);
    }

    private static KeyPair generateKeyPair(int size, Provider[] provider, int ct) throws NoSuchAlgorithmException {
        KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA", provider[(ct >> 1) & 1]);
        kg.initialize(size);
        return kg.generateKeyPair();
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

    private static byte[] strip(byte[] a) {
        int ofs;

        for (ofs = 0; ofs < a.length; ofs++) {
            if (a[ofs] != 0) {
                break;
            }
        }

        byte[] res = new byte[a.length - ofs];
        System.arraycopy(a, ofs, res, 0, res.length);
        return (res);
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
