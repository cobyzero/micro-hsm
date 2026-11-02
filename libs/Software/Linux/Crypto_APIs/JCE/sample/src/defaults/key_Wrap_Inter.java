package defaults;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import CryptoServerAPI.CryptoServerException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import CryptoServerJCE.CryptoServerProvider;
import CryptoServerJCE.CryptoServerRSAKeyGenParameterSpec;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * Test Wrap/Unwrap interacting with other providers
 */
public class key_Wrap_Inter {
    public static class RSAKeyPairAndSpec {
        public RSAKeyPairAndSpec() {
        }

        public RSAPrivateKeySpec getRsaKeySpec() {
            System.out.println("LEN " + this.rsaKeySpec.getModulus().bitLength());
            return rsaKeySpec;
        }

        public void setRsaKeySpec(RSAPrivateKeySpec rsaKeySpec) {
            this.rsaKeySpec = rsaKeySpec;
        }

        public KeyPair getKeyPair() {
            return keyPair;
        }

        public void setKeyPair(KeyPair keyPair) {
            this.keyPair = keyPair;
        }

        private KeyPair keyPair = null;
        private RSAPrivateKeySpec rsaKeySpec = null;
    }

    static class RSATestKey {
        final static String modulus = "B7F3893AAB150BAFECC1931097893C38751AD728DD56DEB8F1A41097755B5E0664FF32FD902B04EDCFD5E2EF8330FDF07C15F9C2229E53F71446EEDBC82BEA3D1679B2BBC07B269D0832D098B3478189CB1FD9F770ED5231EE9AA05BEBE2D0F13F4813F919EB8B3B14AEEE0EE22EDEB152CB5B5798712CDE28273B7E5AB232EB";
        final static String pExponent = "010001";
        final static String sExponent = "0C69C84467C01B524B5942B9D76800E2D47033BDC3B5F580A879C84ED8320AB5C6C1FBE8657EA9ADFC9CF3DBF2CFEF0AF7ECA9B6828C89A0FE42CD2292AEF7F6FB0B8BC61EAE635CE3ACAADACBB0609666266D28B2760483F169C05E672C5C88D2B5B0F66C6474AA7E75A3D526EFBD865D4CD8457DD8F9D31C4B095827C6B3AD";
        final static String primeP = "D19916EC3E718F393467AD608813306B58F763EF6F1A8FE1251AAAE720D1A6F0E552F95DE53C0FECDFFE0ED9E541FC00F83393C9E1B26789D3A779ACA9A5C905";
        final static String primeQ = "E0ACED5548DFF0A24147FEDE87B22505DC11FBC4F080C3E17A11BA588AE2A40AFCFDF352F9031F8F344E909C2ECCD912E2BA6B864C2DE6CFB4F50E03C17F0F2F";
        final static String coeff = "9EC636117E558F3A1C9E03E54A1FADD9F0A6728F34C5842B6F557D58C92BCB243FDB62AA9751B5AA24B4B5129B253ED97D3A69818C7AD2AA6483C2473C1E52F7";
        final static String pExpP = "9D165DC5C5AF1AA6C70E05355A06F7BD1CBA9D5DB0297A3845B4CCEDD8FD085F77A04E60FF139AE3EFA4DBC0974072FCCF08E8F4DF80F474A9FAD50881454D79";
        final static String pExpQ = "7332D781EA1AC0A4413AAC08E7A4C4ECEB38E151CA4B0BA499D56B29A914AA2DE42845D1DE51E6A5A39940F683DC8ED4EB21D0AE0C7360AC5149710525FA830B";

        // Certificate with corresponding to RSA previous data
        final static String selfSignedCertificate = "-----BEGIN CERTIFICATE-----\n"
                + "MIICwDCCAikCFB4ikxt2YD9blBZhiAEkKohpFMwZMA0GCSqGSIb3DQEBCwUAMIGe\n"
                + "MQswCQYDVQQGEwJFUzEPMA0GA1UECAwGTWFkcmlkMRowGAYDVQQHDBFSaXZhcy1W\n"
                + "YWNpYW1hZHJpZDEQMA4GA1UECgwHVXRpbWFjbzEVMBMGA1UECwwMU3BhbmlzaCBU\n"
                + "ZWFtMRUwEwYDVQQDDAxTcGFuaXNoIFRlYW0xIjAgBgkqhkiG9w0BCQEWE3N1cHBv\n"
                + "cnRAdXRpbWFjby5jb20wHhcNMjQwOTE4MTAxMjU4WhcNMzQwOTE2MTAxMjU4WjCB\n"
                + "njELMAkGA1UEBhMCRVMxDzANBgNVBAgMBk1hZHJpZDEaMBgGA1UEBwwRUml2YXMt\n"
                + "VmFjaWFtYWRyaWQxEDAOBgNVBAoMB1V0aW1hY28xFTATBgNVBAsMDFNwYW5pc2gg\n"
                + "VGVhbTEVMBMGA1UEAwwMU3BhbmlzaCBUZWFtMSIwIAYJKoZIhvcNAQkBFhNzdXBw\n"
                + "b3J0QHV0aW1hY28uY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC384k6\n"
                + "qxULr+zBkxCXiTw4dRrXKN1W3rjxpBCXdVteBmT/Mv2QKwTtz9Xi74Mw/fB8FfnC\n"
                + "Ip5T9xRG7tvIK+o9Fnmyu8B7Jp0IMtCYs0eBicsf2fdw7VIx7pqgW+vi0PE/SBP5\n"
                + "GeuLOxSu7g7iLt6xUstbV5hxLN4oJzt+WrIy6wIDAQABMA0GCSqGSIb3DQEBCwUA\n"
                + "A4GBAAxwRxXRIT2O3KnZflExhUK1oWbgNhvWjsYfAr8BgpI7+02YEcu7AxmpPVRf\n"
                + "/oewJz+qbYBV4YiXiPN8ASVhQUfkviaj6esg2+y9tSQSddkQpJeEOXV5sHbx5dCk\n"
                + "iW84o++/b9nnXTdkR77CC4Z86F0bGgDR8NR+Ppu82AEIiGCH\n"
                + "-----END CERTIFICATE-----";

        public static RSAKeyPairAndSpec genAnExportRSAKey(Provider cryptoServerProvider) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException {
            CryptoServerRSAKeyGenParameterSpec cryptoServerRSAKeyGenParameterSpec =
                    new CryptoServerRSAKeyGenParameterSpec(512, new BigInteger("010001", 16));
            cryptoServerRSAKeyGenParameterSpec.setPlainExportable(true);
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", cryptoServerProvider);
            keyPairGenerator.initialize(cryptoServerRSAKeyGenParameterSpec, null);
            KeyPair rsaKeyPair = keyPairGenerator.generateKeyPair();

            PrivateKey rsaPrivateKey = rsaKeyPair.getPrivate();
            KeyFactory secretKeyFactory = KeyFactory.getInstance("RSA", cryptoServerProvider);
            RSAPrivateKeySpec rsaKeySpec = (RSAPrivateKeySpec) secretKeyFactory.getKeySpec(rsaPrivateKey, RSAPrivateKeySpec.class);
            RSAKeyPairAndSpec keyAndSpec = new key_Wrap_Inter.RSAKeyPairAndSpec();
            keyAndSpec.setRsaKeySpec(rsaKeySpec);
            keyAndSpec.setKeyPair(rsaKeyPair);
            return keyAndSpec;
        }

        public static Key getRSAPrivateKeyFromSpec(RSAPrivateKeySpec rsaKeySpec, Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory kf = KeyFactory.getInstance("RSA", provider);
            return kf.generatePrivate(rsaKeySpec);
        }

        public static Key getRSAPrivateKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
            RSAPrivateCrtKeySpec prvCrtKeySpec = new RSAPrivateCrtKeySpec(new BigInteger(modulus, 16),
                    new BigInteger(pExponent, 16),
                    new BigInteger(sExponent, 16),
                    new BigInteger(primeP, 16),
                    new BigInteger(primeQ, 16),
                    new BigInteger(pExpP, 16),
                    new BigInteger(pExpQ, 16),
                    new BigInteger(coeff, 16));

            return getRSAPrivateKeyFromSpec(prvCrtKeySpec, provider);
        }

        /**
         * @return a X509 Certificate corresponding to Test RSA data
         * @throws CertificateException Certificate exception
         */
        public static X509Certificate getRSAX509Certificate() throws CertificateException {
            InputStream is = new ByteArrayInputStream(selfSignedCertificate.getBytes());
            CertificateFactory cf = CertificateFactory.getInstance("x.509");
            return (X509Certificate) cf.generateCertificate(is);
        }

        public static Key getPublicKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory kf = KeyFactory.getInstance("RSA", provider);

            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(modulus, 16),
                    new BigInteger(pExponent, 16));
            return kf.generatePublic(pubKeySpec);
        }
    }

    private static class SecretWrapKey {
        final static byte[] aesKeyBytes = {(byte) 0xB7, (byte) 0xF3, (byte) 0x89, (byte) 0x3A, (byte) 0xAB, (byte) 0x15, (byte) 0x0B, (byte) 0xAF,
                (byte) 0xEC, (byte) 0xC1, (byte) 0x93, (byte) 0x10, (byte) 0x97, (byte) 0x89, (byte) 0x3C, (byte) 0x38,
                (byte) 0x75, (byte) 0x1A, (byte) 0xD7, (byte) 0x28, (byte) 0xDD, (byte) 0x56, (byte) 0xDE, (byte) 0xB8,
                (byte) 0xF1, (byte) 0xA4, (byte) 0x10, (byte) 0x97, (byte) 0x75, (byte) 0x5B, (byte) 0x5E, (byte) 0x06};

        final static byte[] des3KeyBytes = {(byte) 0xB7, (byte) 0xF3, (byte) 0x89, (byte) 0x3A, (byte) 0xAB, (byte) 0x15, (byte) 0x0B, (byte) 0xAF,
                (byte) 0xEC, (byte) 0xC1, (byte) 0x93, (byte) 0x10, (byte) 0x97, (byte) 0x89, (byte) 0x3C, (byte) 0x38,
                (byte) 0x75, (byte) 0x1A, (byte) 0xD7, (byte) 0x28, (byte) 0xDD, (byte) 0x56, (byte) 0xDE, (byte) 0xB8};

        public static SecretKey getKey(Provider provider, String algo) throws NoSuchAlgorithmException, InvalidKeySpecException {
            if (algo.equals("AES")) {
                SecretKeySpec aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
                SecretKeyFactory kf = SecretKeyFactory.getInstance("AES", provider);
                return kf.generateSecret(aesKeySpec);
            }
            SecretKeySpec aesKeySpec = new SecretKeySpec(des3KeyBytes, "DESede");
            SecretKeyFactory kf = SecretKeyFactory.getInstance("DESede", provider);
            return kf.generateSecret(aesKeySpec);
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE : Interoperability demo ---\n");

        CryptoServerProvider cryptoServerProvider = initCryptoServer(args);

        Provider bc_provider = new BouncyCastleProvider();
        Security.addProvider(bc_provider);

        // Algorithms for wrapping
        String[] wrapAlgorithms = new String[]{"AES/ECB/PKCS5PADDING", "AES/OFB/PKCS5PADDING", "RSA/ECB/PKCS1Padding"};
        // Algorithms for En/de-cryption
        String[] cipherAlgorithms = new String[]{"AES/ECB/PKCS5PADDING", "AES/ECB/NOPADDING", "AES/OFB128/PKCS5Padding", "DESede/ECB/NOPADDING", "DESede/CBC/PKCS5PADDING", "RSA/ECB/PKCS1Padding"};
        // list of two providers
        Provider[] provider = {cryptoServerProvider, bc_provider};

        try {
            // for all combinations
            for (int ct = 0; ct <= 2; ct++) {
                Provider wrapProvider = provider[ct & 1];
                Provider unwrapProvider = provider[(ct >> 1) & 1];

                System.out.println("\nWrap on  : " + wrapProvider.getName());
                System.out.println("Unwrap on: " + unwrapProvider.getName());

                // Key pair:
                Key publicKey = RSATestKey.getPublicKey(wrapProvider);
                Key privateKey = (PrivateKey) RSATestKey.getRSAPrivateKey(unwrapProvider);

                byte[] testData = "This is a hello world test".getBytes();

                runInteroperabilityTests(cipherAlgorithms, testData, wrapAlgorithms, wrapProvider, unwrapProvider, publicKey, privateKey);
            }
        } catch (Exception ex) {
            throw ex;
        } finally {
            // logoff
            cryptoServerProvider.close();
        }

        System.out.println("Done");
    }

    private static void runInteroperabilityTests(String[] cipherAlgorithms, byte[] testData, String[] wrapAlgorithms, Provider wrapProvider, Provider unwrapProvider, Key publicKey, Key privateKey) throws Exception {
        for (String cipherAlgorithm : cipherAlgorithms) {
            System.out.println("\nUsing " + cipherAlgorithm + " for en/decryption");
            testData = normalizeNoPaddingInput(cipherAlgorithm, testData);

            performWrapUnwrapTest(testData, wrapAlgorithms, wrapProvider, unwrapProvider, publicKey, privateKey, cipherAlgorithm);
        } // end wrapAlgorithms for
    }

    private static void performWrapUnwrapTest(byte[] testData, String[] wrapAlgorithms, Provider wrapProvider, Provider unwrapProvider, Key publicKey, Key privateKey, String cipherAlgorithm) throws Exception {
        Key wrapkey;
        Key unwrapkey;
        for (String wrapAlgorithm : wrapAlgorithms) {
            if (wrapAlgorithm.contains("RSA")) {
                if (cipherAlgorithm.contains("RSA")) {
                    continue; // ==> Wrap RSA with RSA case.
                }
                wrapkey = RSATestKey.getPublicKey(wrapProvider);
                unwrapkey = (PrivateKey) RSATestKey.getRSAPrivateKey(unwrapProvider);
            } else {
                unwrapkey = wrapAlgorithm.contains("AES") ? SecretWrapKey.getKey(unwrapProvider, "AES") : SecretWrapKey.getKey(unwrapProvider, "DESede");
                wrapkey = wrapAlgorithm.contains("AES") ? SecretWrapKey.getKey(wrapProvider, "AES") : SecretWrapKey.getKey(wrapProvider, "DESede");
            }
            Key targetKey;
            Key targetKey2 = null;
            if (cipherAlgorithm.contains("RSA")) {
                if (wrapProvider instanceof CryptoServerProvider) {
                    RSAKeyPairAndSpec rsaKeyAndSpec = RSATestKey.genAnExportRSAKey(wrapProvider);
                    targetKey2 = rsaKeyAndSpec.getKeyPair().getPrivate();
                    targetKey = rsaKeyAndSpec.getKeyPair().getPublic();
                } else {
                    targetKey = RSATestKey.getPublicKey(wrapProvider);
                    targetKey2 = (PrivateKey) RSATestKey.getRSAPrivateKey(wrapProvider);
                }
            } else {
                targetKey = generateKey(wrapProvider, cipherAlgorithm.contains("DESede") ? "DESede" : "AES"); // generateDESKey(bc_provider);
            }

            // encrypt
            byte[] encryptionIv = cipherAlgorithm.contains("AES") ? getRandom(16) : getRandom(8);
            IvParameterSpec encryptionIvSpec = new IvParameterSpec(encryptionIv);
            byte[] crypto = encryptData(cipherAlgorithm, wrapProvider, targetKey, encryptionIvSpec, testData);
            byte[] iv = wrapAlgorithm.contains("AES") ? getRandom(16) : getRandom(8);

            // WRAP (export)
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            byte[] wrappedKey = wrapKey(wrapAlgorithm, wrapProvider, publicKey, wrapkey, ivSpec, targetKey2, targetKey);

            // unwrap (import)
            Key unwrappedKey = unwrapKey(cipherAlgorithm, wrapAlgorithm, unwrapProvider, privateKey, unwrapkey, ivSpec, targetKey2, wrappedKey);

            // decrypt
            byte[] plain = decryptData(cipherAlgorithm, unwrapProvider, unwrappedKey, encryptionIvSpec, crypto);

            verifyResult(wrapAlgorithm, plain, testData);
        } // end cipherAlgorithms for
    }

    private static void verifyResult(String wrapAlgorithm, byte[] plain, byte[] testData) throws Exception {
        if (!Arrays.equals(plain, testData)) {
            throw new Exception("En-/Decryption failed (" + wrapAlgorithm + ")");
        } else {
            System.out.println("En/Decryption works!! (" + wrapAlgorithm + ")");
        }
    }

    private static byte[] decryptData(String cipherAlgorithm, Provider unwrapProvider, Key unwrappedKey, IvParameterSpec encryptionIvSpec, byte[] crypto) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher testCipherCS = Cipher.getInstance(cipherAlgorithm, unwrapProvider);

        if (cipherAlgorithm.indexOf("ECB") <= 0 && cipherAlgorithm.indexOf("GCM") <= 0 && cipherAlgorithm.indexOf("CCM") <= 0) {
            testCipherCS.init(Cipher.DECRYPT_MODE, unwrappedKey, encryptionIvSpec);
        } else {
            testCipherCS.init(Cipher.DECRYPT_MODE, unwrappedKey);
        }

        return testCipherCS.doFinal(crypto);
    }

    private static Key unwrapKey(String cipherAlgorithm, String wrapAlgorithm, Provider unwrapProvider, Key privateKey, Key unwrapkey, IvParameterSpec ivSpec, Key targetKey2, byte[] wrappedKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher wrapCipher;
        wrapCipher = Cipher.getInstance(wrapAlgorithm, unwrapProvider);
        if (wrapAlgorithm.contains("RSA") || wrapAlgorithm.contains("DSA")) {
            wrapCipher.init(Cipher.UNWRAP_MODE, privateKey);
        } else if (wrapAlgorithm.indexOf("ECB") > 0) {
            wrapCipher.init(Cipher.UNWRAP_MODE, unwrapkey);
        } else {
            wrapCipher.init(Cipher.UNWRAP_MODE, unwrapkey, ivSpec);
        }

        Key unwrappedKey = null;
        if (targetKey2 != null) {
            unwrappedKey = wrapCipher.unwrap(wrappedKey, cipherAlgorithm.contains("RSA") ? "RSA" : "DSA", Cipher.PRIVATE_KEY);
        } else {
            unwrappedKey = wrapCipher.unwrap(wrappedKey, cipherAlgorithm.contains("DES") ? "DES" : "AES", Cipher.SECRET_KEY);
        }
        return unwrappedKey;
    }

    private static byte[] wrapKey(String wrapAlgorithm, Provider wrapProvider, Key publicKey, Key wrapkey, IvParameterSpec ivSpec, Key targetKey2, Key targetKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException {
        byte[] wrappedKey;
        Cipher wrapCipher;
        wrapCipher = Cipher.getInstance(wrapAlgorithm, wrapProvider);
        if (wrapAlgorithm.contains("RSA") || wrapAlgorithm.contains("DSA")) {
            wrapCipher.init(Cipher.WRAP_MODE, publicKey);
        } else if (wrapAlgorithm.indexOf("ECB") > 0) {
            wrapCipher.init(Cipher.WRAP_MODE, wrapkey);
        } else {
            wrapCipher.init(Cipher.WRAP_MODE, wrapkey, ivSpec);
        }

        wrappedKey = targetKey2 != null ? wrapCipher.wrap(targetKey2) : wrapCipher.wrap(targetKey);
        return wrappedKey;
    }

    private static byte[] encryptData(String cipherAlgorithm, Provider wrapProvider, Key targetKey, IvParameterSpec encryptionIvSpec, byte[] testData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher testCipher = Cipher.getInstance(cipherAlgorithm, wrapProvider);
        if (cipherAlgorithm.indexOf("ECB") > 0) {
            testCipher.init(Cipher.ENCRYPT_MODE, targetKey);
        } else {
            testCipher.init(Cipher.ENCRYPT_MODE, targetKey, encryptionIvSpec);
        }

        return testCipher.doFinal(testData);
    }

    private static byte[] normalizeNoPaddingInput(String cipherAlgorithm, byte[] testData) {
        if (cipherAlgorithm.contains("NOPADDING")) {
            int len = testData.length;
            if (len % 16 != 0) {
                final byte[] testData2 = new byte[16];
                for (int i = 0; i < testData2.length; i++) {
                    testData2[i] = testData[i];
                }
                testData = testData2;
            }
        }
        return testData;
    }

    private static CryptoServerProvider initCryptoServer(String[] args) throws IOException, CryptoServerException {
        CryptoServerProvider cryptoServerProvider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(key_Wrap_Inter.class.getResourceAsStream("/CryptoServer.cfg"));
        System.out.println("Device  : " + cryptoServerProvider.getCryptoServer().getDevice());
        cryptoServerProvider.loginPassword("JCE", "12345678");
        cryptoServerProvider.setProperty("Export", "1"); // Globally allow key export
        return cryptoServerProvider;
    }

    public static SecretKey generateKey(Provider provider, String algorithm) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(algorithm, provider);
        int size = algorithm.contains("AES") ? 256 : 112;
        kg.init(size);

        return kg.generateKey();
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
}
