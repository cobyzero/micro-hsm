package defaults;

import CryptoServerJCE.*;

import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * Import keys
 */
public class key_Import {
    private static class AESTestKey {
        final static byte[] aesKeyBytes = {(byte) 0xB7, (byte) 0xF3, (byte) 0x89, (byte) 0x3A, (byte) 0xAB, (byte) 0x15, (byte) 0x0B, (byte) 0xAF,
                (byte) 0xEC, (byte) 0xC1, (byte) 0x93, (byte) 0x10, (byte) 0x97, (byte) 0x89, (byte) 0x3C, (byte) 0x38,
                (byte) 0x75, (byte) 0x1A, (byte) 0xD7, (byte) 0x28, (byte) 0xDD, (byte) 0x56, (byte) 0xDE, (byte) 0xB8,
                (byte) 0xF1, (byte) 0xA4, (byte) 0x10, (byte) 0x97, (byte) 0x75, (byte) 0x5B, (byte) 0x5E, (byte) 0x06};

        public static Key getKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
            SecretKeySpec aesKeySpec = new SecretKeySpec(aesKeyBytes, "AES");
            SecretKeyFactory kf = SecretKeyFactory.getInstance("AES", provider);
            return kf.generateSecret(aesKeySpec);
        }
    }

    private static class DESTestKey {
        final static byte[] desKeyBytes = {(byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11,
                (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x11, (byte) 0x13};

        public static Key getKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
            SecretKeySpec desKeySpec = new SecretKeySpec(desKeyBytes, "DES");
            SecretKeyFactory kf = SecretKeyFactory.getInstance("DES", provider);
            return kf.generateSecret(desKeySpec);
        }
    }

    private static class RSATestKey {
        final static String modulus = "B7F3893AAB150BAFECC1931097893C38751AD728DD56DEB8F1A41097755B5E0664FF32FD902B04EDCFD5E2EF8330FDF07C15F9C2229E53F71446EEDBC82BEA3D1679B2BBC07B269D0832D098B3478189CB1FD9F770ED5231EE9AA05BEBE2D0F13F4813F919EB8B3B14AEEE0EE22EDEB152CB5B5798712CDE28273B7E5AB232EB";
        final static String pExponent = "010001";
        final static String sExponent = "0C69C84467C01B524B5942B9D76800E2D47033BDC3B5F580A879C84ED8320AB5C6C1FBE8657EA9ADFC9CF3DBF2CFEF0AF7ECA9B6828C89A0FE42CD2292AEF7F6FB0B8BC61EAE635CE3ACAADACBB0609666266D28B2760483F169C05E672C5C88D2B5B0F66C6474AA7E75A3D526EFBD865D4CD8457DD8F9D31C4B095827C6B3AD";
        final static String primeP = "D19916EC3E718F393467AD608813306B58F763EF6F1A8FE1251AAAE720D1A6F0E552F95DE53C0FECDFFE0ED9E541FC00F83393C9E1B26789D3A779ACA9A5C905";
        final static String primeQ = "E0ACED5548DFF0A24147FEDE87B22505DC11FBC4F080C3E17A11BA588AE2A40AFCFDF352F9031F8F344E909C2ECCD912E2BA6B864C2DE6CFB4F50E03C17F0F2F";
        final static String coeff = "9EC636117E558F3A1C9E03E54A1FADD9F0A6728F34C5842B6F557D58C92BCB243FDB62AA9751B5AA24B4B5129B253ED97D3A69818C7AD2AA6483C2473C1E52F7";
        final static String pExpP = "9D165DC5C5AF1AA6C70E05355A06F7BD1CBA9D5DB0297A3845B4CCEDD8FD085F77A04E60FF139AE3EFA4DBC0974072FCCF08E8F4DF80F474A9FAD50881454D79";
        final static String pExpQ = "7332D781EA1AC0A4413AAC08E7A4C4ECEB38E151CA4B0BA499D56B29A914AA2DE42845D1DE51E6A5A39940F683DC8ED4EB21D0AE0C7360AC5149710525FA830B";

        public static Key getPrivateCRTKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory kf = KeyFactory.getInstance("RSA", provider);

            RSAPrivateCrtKeySpec prvCrtKeySpec = new RSAPrivateCrtKeySpec(new BigInteger(modulus, 16),
                    new BigInteger(pExponent, 16),
                    new BigInteger(sExponent, 16),
                    new BigInteger(primeP, 16),
                    new BigInteger(primeQ, 16),
                    new BigInteger(pExpP, 16),
                    new BigInteger(pExpQ, 16),
                    new BigInteger(coeff, 16));
            return kf.generatePrivate(prvCrtKeySpec);
        }

        public static Key getPrivateKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory kf = KeyFactory.getInstance("RSA", provider);

            RSAPrivateKeySpec prvKeySpec = new RSAPrivateKeySpec(new BigInteger(modulus, 16),
                    new BigInteger(sExponent, 16));
            return kf.generatePrivate(prvKeySpec);
        }

        public static Key getPublicKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
            KeyFactory kf = KeyFactory.getInstance("RSA", provider);

            RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(modulus, 16),
                    new BigInteger(pExponent, 16));
            return kf.generatePublic(pubKeySpec);
        }
    }

    private static class ECTestKey {
        // curve brainpoolP320t1
        final static String primeP = "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E27";
        final static String paramA = "D35E472036BC4FB7E13C785ED201E065F98FCFA6F6F40DEF4F92B9EC7893EC28FCD412B1F1B32E24";
        final static String paramB = "A7F561E038EB1ED560B3D147DB782013064C19F27ED27C6780AAF77FB8A547CEB5B4FEF422340353";
        final static String genX = "925BE9FB01AFC6FB4D3E7D4990010F813408AB106C4F09CB7EE07868CC136FFF3357F624A21BED52";
        final static String genY = "63BA3A7A27483EBF6671DBEF7ABB30EBEE084E58A0B077AD42A5A0989D1EE71B1B9BC0455FB0D2C3";
        final static String order = "D35E472036BC4FB7E13C785ED201E065F98FCFA5B68F12A32D482EC7EE8658E98691555B44C59311";
        final static int cof = 1;
        final static String pubKeyX = "4C687852F26D6CA492D533AFF820007B781E52F06A8518EEA8CAC917D5D86BC4735DAEED9509D473";
        final static String pubKeyY = "554E1D95FE14B1FA842E8DD2CD5B435D47860C73FF7993A82868935E26432A1ED74FC1933011DCE3";
        final static String prvKey = "3F5B81C9C925B5A776C517BFF8105FC7715784AC58AEADCDFAD975825A02A1A603C0FD1C61B32698";

        public static ECParameterSpec getParams()  {
            return new ECParameterSpec(new EllipticCurve(new ECFieldFp(new BigInteger(primeP, 16)),
                    new BigInteger(paramA, 16),
                    new BigInteger(paramB, 16)),
                    new ECPoint(new BigInteger(genX, 16),
                            new BigInteger(genY, 16)),
                    new BigInteger(order, 16), cof);
        }

        public static Key getPrivateKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
            ECPrivateKeySpec prvKeySpec = new ECPrivateKeySpec(new BigInteger(prvKey, 16),
                    getParams());
            KeyFactory kf = KeyFactory.getInstance("EC", provider);
            return kf.generatePrivate(prvKeySpec);
        }

        public static Key getPublicKey(Provider provider) throws NoSuchAlgorithmException, InvalidKeySpecException {
            ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(new ECPoint(new BigInteger(pubKeyX, 16),
                    new BigInteger(pubKeyY, 16)),
                    getParams());
            KeyFactory kf = KeyFactory.getInstance("EC", provider);
            return kf.generatePublic(pubKeySpec);
        }
    }

    // ********************************************************************************
    // main
    // ********************************************************************************
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE: key_Import ---\n");
        final String aesKeyName = "AES_imp_1";
        final String desKeyName = "DES_imp_1";
        final String rsaPublicKeyName = "RSA_pub_imp_1";
        final String rsaPrivateKeyName = "RSA_prv_imp_1";
        final String rsaPrivateKeyName2 = "RSA_prv_imp_2";
        final String ecPublicKeyName = "EC_pub_imp_1";
        final String ecPrivateKeyName = "EC_prv_imp_1";

        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(key_Import.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            // open key store
            KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
            ks.load(null, null);

            importSymmetricKeys(ks, aesKeyName, provider, desKeyName);

            importRsaKeys(ks, rsaPrivateKeyName, provider, rsaPrivateKeyName2, rsaPublicKeyName);

            importEcKeys(ks, ecPrivateKeyName, provider, ecPublicKeyName);

            // list keys
            Enumeration<String> kl = ks.aliases();

            System.out.println("\nKeys:\n");
            System.out.println("Type Name             Creation");
            System.out.println("----------------------------------------");

            while (kl.hasMoreElements()) {
                String name = kl.nextElement();

                if (ks.isKeyEntry(name)) {
                    System.out.print("Key  ");
                }
                if (ks.isCertificateEntry(name)) {
                    System.out.print("Cert ");
                }

                System.out.println(String.format("%-16s %s", name, ks.getCreationDate(name)));
            }
        } catch (Exception ex) {
            throw ex;
        } finally {
            // close
            if (provider != null) {
                provider.close();
            }
        }

        System.out.println("Done");
    }

    private static void importEcKeys(KeyStore ks, String ecPrivateKeyName, CryptoServerProvider provider, String ecPublicKeyName) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException {
        // import private EC key into key store
        System.out.println("import private EC key...");
        ks.setKeyEntry(ecPrivateKeyName, ECTestKey.getPrivateKey(provider), null, provider.getDumyCertificateChain());

        // import public EC key into key store
        System.out.println("import public EC key...");
        ks.setKeyEntry(ecPublicKeyName, ECTestKey.getPublicKey(provider), null, provider.getDumyCertificateChain());
    }

    private static void importSymmetricKeys(KeyStore ks, String aesKeyName, CryptoServerProvider provider, String desKeyName) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException {
        // import AES key into key store
        System.out.println("import AES key...");
        ks.setKeyEntry(aesKeyName, AESTestKey.getKey(provider), null, null);

        // import DES key into key store
        System.out.println("import DES key...");
        ks.setKeyEntry(desKeyName, DESTestKey.getKey(provider), null, null);
    }

    private static void importRsaKeys(KeyStore ks, String rsaPrivateKeyName, CryptoServerProvider provider, String rsaPrivateKeyName2, String rsaPublicKeyName) throws KeyStoreException, NoSuchAlgorithmException, InvalidKeySpecException {
        // import private RSA key into key store
        System.out.println("import private RSA key...");
        ks.setKeyEntry(rsaPrivateKeyName, RSATestKey.getPrivateKey(provider), null, provider.getDumyCertificateChain());

        // import private RSA key (CRT) into key store
        System.out.println("import private RSA key (CRT)...");
        ks.setKeyEntry(rsaPrivateKeyName2, RSATestKey.getPrivateCRTKey(provider), null, provider.getDumyCertificateChain());

        // import public RSA key into key store
        System.out.println("import public RSA key...");
        ks.setKeyEntry(rsaPublicKeyName, RSATestKey.getPublicKey(provider), null, null);
    }
}
