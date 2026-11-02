package defaults;

import CryptoServerJCE.*;
import CryptoServerAPI.*;
import javax.crypto.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 *
 * Test AES encryption / decryption with all key sizes and modes
 */
public class crypt_AES {
    public static void crypt_AES_CS_vs_CS(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - crypt_AES_cs_vs_cs ---\n");
        int[] sizes = {128, 192, 256};

        Algorithm[] modes = {
            new Algorithm("AES/ECB/NOPADDING", null, null),
            new Algorithm("AES/ECB/PKCS5Padding", null, null),
            new Algorithm("AES/CBC/NOPADDING", new IvParameterSpec(getRandom(16)), null),
            new Algorithm("AES/CBC/PKCS5PADDING", new IvParameterSpec(getRandom(16)), null),
            new Algorithm("AES/ECB/ISO10126Padding", null, null),
            new Algorithm("AES/CBC/ISO10126PADDING", new IvParameterSpec(getRandom(16)), null),
            new Algorithm("AES/OFB/NOPADDING", new IvParameterSpec(getRandom(16)), null),
            new Algorithm("AES/OFB/PKCS5Padding", new IvParameterSpec(getRandom(16)), null),
            new Algorithm("AES/OFB/ISO10126PADDING", new IvParameterSpec(getRandom(16)), null),
            new Algorithm("AES/OFB128/NOPADDING", new IvParameterSpec(getRandom(16)), null),
            new Algorithm("AES/OFB128/PKCS5Padding", new IvParameterSpec(getRandom(16)), null),
            new Algorithm("AES/OFB128/ISO10126PADDING", new IvParameterSpec(getRandom(16)), null),
            new Algorithm("AES/GCM/NOPADDING", new GCMParameterSpec(64, getRandom(16)), null),
            new Algorithm("AES/GCM/NOPADDING", new CryptoServerGCMParameterSpec(64, getRandom(16), getRandom(16)), null),
            new Algorithm("AES/CCM/NOPADDING", null, null), // parameters needs total data length, calculated in test
        };

        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(crypt_AES.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            for (int keySize : sizes) {
                System.out.println("Key size: " + keySize);

                // Generate AES aesKey
                SecretKey aesKey = generateAesKey(keySize, provider);

                // for all modes
                for (Algorithm mode : modes) {
                    processAlgorithmMode(keySize, mode, provider, aesKey);
                }
            }

            System.out.println("NO ERRORS!!!!");
        } catch (Exception ex) {
            throw ex;
        } finally {
            // logoff
            closeProvider(provider);
        }

        System.out.println("Done");
    }

    private static void processAlgorithmMode(int keySize, Algorithm mode, CryptoServerProvider provider, SecretKey aesKey) throws Exception {
        String algo = mode.algo;
        System.out.println("algo: " + algo);

        Cipher c = Cipher.getInstance(algo, provider);

        for (int len1 = 0; len1 < 1000; len1 += 177) {
            for (int len2 = 1; len2 < 30; len2 += 3) {
                for (int len3 = 0; len3 < 200; len3 += 19) {
                    len2 = adjustLengthForNoPadding(algo, len1, len2, len3);

                    byte[] data1 = getRandom(len1);
                    byte[] data2 = getRandom(len2);
                    byte[] data3 = getRandom(len3);

                    if (algo.indexOf("/CCM") > 0) {
                        mode.param = new CryptoServerCCMParameterSpec(getRandom(8), getRandom(16), len1 + len2 + len3, 8);
                    }

                    // encrypt with CryptoServer
                    byte[] crypto = encryptWithCryptoServer(mode, c, aesKey, len1, data1, len2, data2, len3, data3);

                    // decrypt with CryptoServer
                    len2 = crypto.length - len1 - len3;
                    byte[] plain = decryptWithCryptoServer(mode, c, aesKey, len1, crypto, len2, len3);

                    // compare data
                    compareData(keySize, mode, data1, data2, data3, plain, len1, len2, len3);
                }
            }
        }
    }

    private static int adjustLengthForNoPadding(String algo, int len1, int len2, int len3) {
        if (!algo.contains("/OFB") && !algo.contains("/GCM") && !algo.contains("/CCM") && algo.contains("NOPADDING")) {
            int len = len1 + len2 + len3;
            if ((len = len % 16) != 0) {
                len2 += 16 - len; // add to 2nd block to ensure that 3rd can be empty!
            }
        }
        return len2;
    }

    private static void closeProvider(CryptoServerProvider provider) {
        if (provider != null) {
            provider.close();
        }
    }

    private static byte[] decryptWithCryptoServer(Algorithm mode, Cipher c, SecretKey aesKey, int len1, byte[] crypto, int len2, int len3) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        initCipher(c, Cipher.DECRYPT_MODE, aesKey, mode);

        byte[] plain = null;

        if (len1 != 0) {
            plain = cat(plain, c.update(crypto, 0, len1));
        }
        if (len2 != 0) {
            plain = cat(plain, c.update(crypto, len1, len2));
        }
        if (len3 != 0) {
            plain = cat(plain, c.doFinal(crypto, len1 + len2, len3));
        } else {
            plain = cat(plain, c.doFinal());
        }
        return plain;
    }

    private static void compareData(int keySize, Algorithm mode, byte[] data1, byte[] data2, byte[] data3, byte[] plain, int len1, int len2, int len3) throws Exception {
        byte[] data = cat(cat(data1, data2), data3);

        if (!Arrays.equals(data, plain)) {
            System.out.println("Keysize=" + keySize + ", mode=" + mode.algo + ", len=" + len1 + "-" + len2 + "-" + len3);

            throw new Exception("En-/Decryption failed");
        }
    }

    private static byte[] encryptWithCryptoServer(Algorithm mode, Cipher c, SecretKey aesKey, int len1, byte[] data1, int len2, byte[] data2, int len3, byte[] data3) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        initCipher(c, Cipher.ENCRYPT_MODE, aesKey, mode);

        byte[] crypto = null;

        if (len1 != 0) {
            crypto = cat(crypto, c.update(data1));
        }
        if (len2 != 0) {
            crypto = cat(crypto, c.update(data2));
        }
        if (len3 != 0) {
            crypto = cat(crypto, c.doFinal(data3));
        } else {
            crypto = cat(crypto, c.doFinal());
        }
        return crypto;
    }

    private static SecretKey generateAesKey(int keySize, CryptoServerProvider provider) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        CryptoServerKeyGenParameterSpec aesParam = new CryptoServerKeyGenParameterSpec(keySize);
        aesParam.setPlainExportable(true);

        KeyGenerator kg = KeyGenerator.getInstance("AES", provider);
        kg.init(aesParam, null);
        return kg.generateKey();
    }

    public static void crypt_AES_CS_vs_BOUNCY(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - crypt_AES_CS_vs_BOUNCY ---\n");
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        String PROV_CIPHER = "BC";

        byte[] iv = getRandom(16);
        byte[] nonce_ccm = getRandom(8);
        byte[] aad = getRandom(16);
        Algorithm[] modes = {
            new Algorithm("AES/ECB/NOPADDING", null, null),
            new Algorithm("AES/ECB/PKCS5Padding", null, null),
            new Algorithm("AES/CBC/NOPADDING", new IvParameterSpec(iv), new IvParameterSpec(iv)),
            new Algorithm("AES/CBC/PKCS5PADDING", new IvParameterSpec(iv), new IvParameterSpec(iv)),
            new Algorithm("AES/ECB/ISO10126Padding", null, null),
            new Algorithm("AES/CBC/ISO10126PADDING", new IvParameterSpec(iv), new IvParameterSpec(iv)),
            new Algorithm("AES/OFB/NOPADDING", new IvParameterSpec(iv), new IvParameterSpec(iv)),
            new Algorithm("AES/OFB/PKCS5Padding", new IvParameterSpec(iv), new IvParameterSpec(iv)),
            new Algorithm("AES/OFB/ISO10126PADDING", new IvParameterSpec(iv), new IvParameterSpec(iv)),
            new Algorithm("AES/OFB128/NOPADDING", new IvParameterSpec(iv), new IvParameterSpec(iv)),
            new Algorithm("AES/OFB128/PKCS5Padding", new IvParameterSpec(iv), new IvParameterSpec(iv)),
            new Algorithm("AES/OFB128/ISO10126PADDING", new IvParameterSpec(iv), new IvParameterSpec(iv)),
            new Algorithm("AES/GCM/NOPADDING", new GCMParameterSpec(64, iv), new GCMParameterSpec(64, iv)),
            new Algorithm("AES/GCM/NOPADDING", new CryptoServerGCMParameterSpec(64, iv, aad), new GCMParameterSpec(64, iv)),
            new Algorithm("AES/CCM/NOPADDING", null, new GCMParameterSpec(64, nonce_ccm)), // parameters needs total data length, calculated in test
        };

        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(crypt_AES.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            int[] sizes = {192, 256};

            verifyAesCompatibilityForKeySizes(sizes, PROV_CIPHER, modes, provider, nonce_ccm, aad);
            System.out.println("NO ERRORS!!!!");
        } catch (Exception ex) {
            throw ex;
        } finally {
            // logoff
            closeProvider(provider);
        }

        System.out.println("Done");
    }

    private static void verifyAesCompatibilityForKeySizes(int[] sizes, String PROV_CIPHER, Algorithm[] modes, CryptoServerProvider provider, byte[] nonce_ccm, byte[] aad) throws Exception {
        for (int keySize : sizes) {
            SecretKey bouncyKey = generateKey(keySize, PROV_CIPHER);

            SecretKeySpec jceKey = new SecretKeySpec(bouncyKey.getEncoded(), "AES");

            System.out.println("Key size: " + keySize);

            // for all modes
            for (Algorithm mode : modes) {
                verifyAesModeCompatibility(keySize, mode, provider, PROV_CIPHER, nonce_ccm, aad, jceKey, bouncyKey);
            }
        }
    }

    private static void verifyAesModeCompatibility(int keySize, Algorithm mode, CryptoServerProvider provider, String PROV_CIPHER, byte[] nonce_ccm, byte[] aad, SecretKeySpec jceKey, SecretKey bouncyKey) throws Exception {
        String algo = mode.algo;
        System.out.println("algo: " + algo);

        Cipher c = Cipher.getInstance(algo, provider);
        Cipher c2 = Cipher.getInstance(algo, PROV_CIPHER);

        for (int len1 = 0; len1 < 1000; len1 += 177) {
            for (int len2 = 0; len2 < 30; len2 += 3) {
                for (int len3 = 1; len3 < 200; len3 += 19) {
                    len2 = adjustLengthForNoPadding(algo, len1, len2, len3);

                    byte[] data1 = getRandom(len1);
                    byte[] data2 = getRandom(len2);
                    byte[] data3 = getRandom(len3);

                    if (algo.indexOf("/CCM") > 0) {
                        mode.param = new CryptoServerCCMParameterSpec(nonce_ccm, aad, len1 + len2 + len3, 8);
                    }

                    // encrypt with CryptoServer
                    initCipher(c, Cipher.ENCRYPT_MODE, jceKey, mode);

                    if (algo.indexOf("/GCM/") > 0 && mode.param instanceof GCMParameterSpec) {
                        c.updateAAD(aad);
                    }

                    byte[] crypto = encryptChunked(len1, c, data1, len2, data2, len3, data3);

                    // decrypt with Bouncy
                    byte[] plain = decryptWithBouncy(mode, c2, bouncyKey, algo, aad, crypto);

                    // compare data
                    verifyPlaintextMatchesOriginal(keySize, mode, data1, data2, data3, plain, len1, len2, len3);

                    c2 = Cipher.getInstance(algo, PROV_CIPHER);

                    // encrypt with Bouncy
                    crypto = encryptWithBouncy(mode, c2, bouncyKey, algo, aad, plain);

                    // decrypt with CryptoServer
                    initCipher(c, Cipher.DECRYPT_MODE, jceKey, mode);

                    if (algo.indexOf("/GCM/") > 0 && mode.param instanceof GCMParameterSpec) {
                        c.updateAAD(aad);
                    }

                    plain = null;
                    len3 = crypto.length - len1 - len2;

                    plain = decryptChunked(len1, plain, c, crypto, len2, len3);

                    // compare data
                    verifyPlaintextMatchesOriginal(keySize, mode, data1, data2, data3, plain, len1, len2, len3);
                }
            }
        }
    }

    private static void initCipher(Cipher cipher, int opMode, SecretKey key, Algorithm mode) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (mode.param == null) {
            cipher.init(opMode, key);
        } else {
            cipher.init(opMode, key, mode.param);
        }
    }

    private static void verifyPlaintextMatchesOriginal(int keySize, Algorithm mode, byte[] data1, byte[] data2, byte[] data3, byte[] plain, int len1, int len2, int len3) throws Exception {
        byte[] data = cat(cat(data1, data2), data3);

        if (!Arrays.equals(data, plain)) {
            CryptoServerUtil.xtrace(plain);
            CryptoServerUtil.xtrace(data);
            System.out.println("Keysize=" + keySize + ", mode=" + mode.algo + ", len=" + len1 + "-" + len2 + "-" + len3);

            throw new Exception("En-/Decryption failed");
        }
    }

    private static byte[] decryptChunked(int len1, byte[] plain, Cipher c, byte[] crypto, int len2, int len3) throws IllegalBlockSizeException, BadPaddingException {
        if (len1 != 0) {
            plain = cat(plain, c.update(crypto, 0, len1));
        }
        if (len2 != 0) {
            plain = cat(plain, c.update(crypto, len1, len2));
        }
        if (len3 != 0) {
            plain = cat(plain, c.doFinal(crypto, len1 + len2, len3));
        } else {
            plain = cat(plain, c.doFinal());
        }
        return plain;
    }

    private static byte[] encryptChunked(int len1, Cipher c, byte[] data1, int len2, byte[] data2, int len3, byte[] data3) throws IllegalBlockSizeException, BadPaddingException {
        byte[] crypto = null;

        if (len1 != 0) {
            crypto = cat(crypto, c.update(data1));
        }
        if (len2 != 0) {
            crypto = cat(crypto, c.update(data2));
        }
        if (len3 != 0) {
            crypto = cat(crypto, c.doFinal(data3));
        } else {
            crypto = cat(crypto, c.doFinal());
        }
        return crypto;
    }

    private static byte[] encryptWithBouncy(Algorithm mode, Cipher c2, SecretKey bouncyKey, String algo, byte[] aad, byte[] plain) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] crypto;
        if (mode.paramBC == null) {
            c2.init(Cipher.ENCRYPT_MODE, bouncyKey);
        } else {
            c2.init(Cipher.ENCRYPT_MODE, bouncyKey, mode.paramBC);
        }

        if (algo.indexOf("/GCM/") > 0 || algo.indexOf("/CCM/") > 0) {
            c2.updateAAD(aad);
        }

        crypto = c2.doFinal(plain);
        return crypto;
    }

    private static byte[] decryptWithBouncy(Algorithm mode, Cipher c2, SecretKey bouncyKey, String algo, byte[] aad, byte[] crypto) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        if (mode.paramBC == null) {
            c2.init(Cipher.DECRYPT_MODE, bouncyKey);
        } else {
            c2.init(Cipher.DECRYPT_MODE, bouncyKey, mode.paramBC);
        }

        if (algo.indexOf("/GCM/") > 0 || algo.indexOf("/CCM/") > 0) {
            c2.updateAAD(aad);
        }

        return c2.doFinal(crypto);
    }

    private static SecretKey generateKey(int keySize, String PROV_CIPHER) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", PROV_CIPHER);
        keyGenerator.init(keySize);
        return keyGenerator.generateKey();
    }

    public static void main(String[] args) throws Exception {
        crypt_AES_CS_vs_CS(args);
        System.out.println("###########################################################################");
        crypt_AES_CS_vs_BOUNCY(args);
    }

    private static class Algorithm {
        String algo;
        AlgorithmParameterSpec param;
        AlgorithmParameterSpec paramBC;

        public Algorithm(String algo, AlgorithmParameterSpec param, AlgorithmParameterSpec paramBC) {
            this.algo = algo;
            this.param = param;
            this.paramBC = paramBC;
        }
    }

    private static byte[] getRandom(int length) {
        try {
            if (length == 0) {
                return null;
            }

            byte[] buf = new byte[length];
            SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
            rng.nextBytes(buf);
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

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHexString(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
