package defaults;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import CryptoServerJCE.CryptoServerProvider;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 *
 * Test DES encryption / decryption with all key sizes and modes
 */
public class crypt_DES {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - crypt_DES ---\n");

        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        String PROV_CIPHER = "BC";
        String[] modes = {"/ECB/NOPADDING", "/ECB/PKCS5PADDING", "/CBC/NOPADDING", "/CBC/PKCS5PADDING", "/ECB/ISO10126PADDING", "/CBC/ISO10126PADDING"};

        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(crypt_DES.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            int[] key_sizes = {128, 192};

            // for all key sizes
            for (int keySize : key_sizes) {
                processKeySize(keySize, PROV_CIPHER, modes, provider);
            }
            System.out.println("NO ERRORS!!!!");
        } catch (Exception ex) {
            throw ex;
        } finally {
            // logoff
            if (provider != null) {
                provider.close();
            }
        }

        System.out.println("Done");
    }

    private static void processKeySize(int keySize, String PROV_CIPHER, String[] modes, CryptoServerProvider provider) throws Exception {
        System.out.println("Key size: " + keySize);
        String algorithm = (keySize == 64) ? "DES" : "DESede";
        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithm, PROV_CIPHER);
        keyGenerator.init(keySize);
        SecretKey bouncyKey = keyGenerator.generateKey();

        SecretKeySpec jceKey = new SecretKeySpec(bouncyKey.getEncoded(), algorithm);

        // for all modes
        for (String mode : modes) {
            mode = algorithm + mode;
            System.out.println("  mode: " + mode);

            Cipher c = Cipher.getInstance(mode, provider);
            Cipher c2 = Cipher.getInstance(mode, PROV_CIPHER);

            IvParameterSpec ivsp = initIv(mode);

            for (int len1 = 0; len1 < 1000; len1 += 177) {
                byte[] data1 = getRandom(len1);

                for (int len2 = 0; len2 < 30; len2 += 3) {
                    byte[] data2 = getRandom(len2);

                    for (int len3 = 1; len3 < 200; len3 += 19) {
                        len3 = adjustForNoPadding(mode, len1, len2, len3);

                        byte[] data3 = getRandom(len3);

                        // encrypt with CryptoServer
                        byte[] crypto = encryptWithCryptoServer(ivsp, c, jceKey, len1, data1, len2, data2, len3, data3);

                        // decrypt with Sun Provider
                        byte[] plain = decryptWithSun(ivsp, c2, bouncyKey, crypto);

                        // compare data
                        byte[] data = cat(cat(data1, data2), data3);

                        compareData(keySize, mode, data, plain, len1, len2, len3);

                        // encrypt with Sun Provider
                        crypto = encryptWithSun(ivsp, c2, bouncyKey, plain);

                        // decrypt with CryptoServer
                        initCipher(ivsp, c, Cipher.DECRYPT_MODE, jceKey);

                        plain = null;
                        len3 = crypto.length - len1 - len2;

                        plain = decryptWithCryptoServer(len1, plain, c, crypto, len2, len3);

                        // compare data
                        data = cat(cat(data1, data2), data3);

                        compareData(keySize, mode, data, plain, len1, len2, len3);
                    }
                }
            }
        }
    }

    private static void initCipher(IvParameterSpec ivsp, Cipher c, int cipherMode, SecretKeySpec jceKey) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (ivsp == null) {
            c.init(cipherMode, jceKey);
        } else {
            c.init(cipherMode, jceKey, ivsp);
        }
    }

    private static byte[] decryptWithCryptoServer(int len1, byte[] plain, Cipher c, byte[] crypto, int len2, int len3) throws IllegalBlockSizeException, BadPaddingException {
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

    private static void compareData(int keySize, String mode, byte[] data, byte[] plain, int len1, int len2, int len3) throws Exception {
        if (!Arrays.equals(data, plain)) {
            System.out.println("Keysize=" + keySize + ", mode=" + mode + ", len=" + len1 + "-" + len2 + "-" + len3);

            throw new Exception("En-/Decryption failed");
        }
    }

    private static byte[] encryptWithSun(IvParameterSpec ivsp, Cipher c2, SecretKey bouncyKey, byte[] plain) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        byte[] crypto;
        if (ivsp == null) {
            c2.init(Cipher.ENCRYPT_MODE, bouncyKey);
        } else {
            c2.init(Cipher.ENCRYPT_MODE, bouncyKey, ivsp);
        }

        crypto = c2.doFinal(plain);
        return crypto;
    }

    private static byte[] decryptWithSun(IvParameterSpec ivsp, Cipher c2, SecretKey bouncyKey, byte[] crypto) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        if (ivsp == null) {
            c2.init(Cipher.DECRYPT_MODE, bouncyKey);
        } else {
            c2.init(Cipher.DECRYPT_MODE, bouncyKey, ivsp);
        }

        return c2.doFinal(crypto);
    }

    private static byte[] encryptWithCryptoServer(IvParameterSpec ivsp, Cipher c, SecretKeySpec jceKey, int len1, byte[] data1, int len2, byte[] data2, int len3, byte[] data3) throws InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        initCipher(ivsp, c, Cipher.ENCRYPT_MODE, jceKey);

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

    private static int adjustForNoPadding(String mode, int len1, int len2, int len3) {
        if (mode.contains("NOPADDING")) {
            int len = len1 + len2 + len3;

            if ((len = len % 8) != 0) {
                len3 += 8 - len;
            }
        }
        return len3;
    }

    private static IvParameterSpec initIv(String mode) {
        if (mode.contains("/CBC/")) {
            return new IvParameterSpec(getRandom(8));
        }
        return null;
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
