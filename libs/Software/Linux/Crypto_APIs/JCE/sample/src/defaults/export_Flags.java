package defaults;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import CryptoServerJCE.CryptoServerKeyGenParameterSpec;
import CryptoServerJCE.CryptoServerKeySpec;
import CryptoServerJCE.CryptoServerProvider;
import CryptoServerJCE.CryptoServerRSAKeyGenParameterSpec;
import CryptoServerJCE.CryptoServerRSAPrivateKey;
import CryptoServerJCE.CryptoServerSecretKey;
import CryptoServerJCE.CryptoServerUnwrapAlgorithmParameterSpec;

public class export_Flags {
    public static void main(String[] args) throws Exception {
        importWithExportFlag(args);

        unwrapWithExportFlag(args);
    }

    public static void importWithExportFlag(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - importWithExportFlag ---\n");
        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(export_Flags.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            testImportCustomPrivateRSA_exportable_spec(provider, 2048, true, true);
            testImportCustomPrivateRSA_exportable_spec(provider, 2048, false, true);

            testImportCustomPrivateDSA_exportable_spec(provider, 1024, true, true);
            testImportCustomPrivateDSA_exportable_spec(provider, 1024, false, true);

            testImportCustomPrivateEC_exportable_spec(provider, "secp256r1", true, true);
            testImportCustomPrivateEC_exportable_spec(provider, "secp256r1", false, true);

            testImportCustomSymmetric_exportable_spec(provider, "AES", true, true);
            testImportCustomSymmetric_exportable_spec(provider, "AES", false, true);

            testImportCustomSymmetric_exportable_spec(provider, "DESede", true, true);
            testImportCustomSymmetric_exportable_spec(provider, "DESede", false, true);

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

    private static void testImportCustomPrivateDSA_exportable_spec(CryptoServerProvider cryptoServerProvider, int keySize, boolean allowExport, boolean allowPlainExport) throws Exception {
        DSAPrivateKeySpec privateKeySpecJCE = null;
        Provider bouncyProvider = new BouncyCastleProvider();

        KeyPairGenerator kg = KeyPairGenerator.getInstance("DSA", bouncyProvider);
        kg.initialize(keySize);
        KeyPair keyPair = kg.generateKeyPair();

        KeyFactory kf = KeyFactory.getInstance("DSA", bouncyProvider);
        DSAPrivateKeySpec privateKeySpec = kf.getKeySpec(keyPair.getPrivate(), DSAPrivateKeySpec.class);

        KeyFactory kfJCE = KeyFactory.getInstance("DSA", cryptoServerProvider);
        CryptoServerKeySpec paramsImport = new CryptoServerKeySpec(privateKeySpec);
        paramsImport.setExportable(allowExport);
        paramsImport.setPlainExportable(allowPlainExport);
        PrivateKey privateJCE = kfJCE.generatePrivate(paramsImport);

        privateKeySpecJCE = kfJCE.getKeySpec(privateJCE, DSAPrivateKeySpec.class);
        if (privateKeySpecJCE == null) {
            throw new Exception("Private DSA key could not be exported");
        }
        if (privateKeySpec.getG().compareTo(privateKeySpecJCE.getG()) != 0) {
            throw new Exception("The value G is different");
        }
        if (privateKeySpec.getP().compareTo(privateKeySpecJCE.getP()) != 0) {
            throw new Exception("The value P is different");
        }
        if (privateKeySpec.getQ().compareTo(privateKeySpecJCE.getQ()) != 0) {
            throw new Exception("The value Q is different");
        }
        if (privateKeySpec.getX().compareTo(privateKeySpecJCE.getX()) != 0) {
            throw new Exception("The value X is different");
        }
    }

    private static void testImportCustomPrivateEC_exportable_spec(CryptoServerProvider cryptoServerProvider, String curveName, boolean allowExport, boolean allowPlainExport) throws Exception {
        Provider bouncyProvider = new BouncyCastleProvider();

        KeyPairGenerator kg = KeyPairGenerator.getInstance("EC", bouncyProvider);
        kg.initialize(new ECGenParameterSpec(curveName));
        KeyPair keyPair = kg.generateKeyPair();

        importPrivateKeyToCryptoServer(keyPair, "EC", bouncyProvider, cryptoServerProvider, ECPrivateKeySpec.class, allowExport, allowPlainExport);
    }

    private static void testImportCustomPrivateRSA_exportable_spec(CryptoServerProvider cryptoServerProvider, int keySize, boolean allowExport, boolean allowPlainExport) throws Exception {
        Provider bouncyProvider = new BouncyCastleProvider();
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", bouncyProvider);
        kpg.initialize(keySize, null);
        KeyPair keyPair = kpg.generateKeyPair();

        importPrivateKeyToCryptoServer(keyPair, "RSA", bouncyProvider, cryptoServerProvider, RSAPrivateKeySpec.class, allowExport, allowPlainExport);
    }

    private static void testImportCustomSymmetric_exportable_spec(CryptoServerProvider cryptoServerProvider, String alg, boolean allowExport, boolean allowPlainExport) throws Exception {
        SecretKeySpec privateKeySpecJCE = null;
        Provider bouncyProvider = new BouncyCastleProvider();

        KeyGenerator kg = KeyGenerator.getInstance(alg, bouncyProvider);

        kg.init("AES".equals(alg) ? 256 : 192);
        SecretKey secretKey = kg.generateKey();

        SecretKeyFactory kf = SecretKeyFactory.getInstance(alg, bouncyProvider);
        SecretKeySpec privateKeySpec = (SecretKeySpec) kf.getKeySpec(secretKey, SecretKeySpec.class);

        SecretKeyFactory kfJCE = SecretKeyFactory.getInstance(alg, cryptoServerProvider);
        CryptoServerKeySpec paramsImport = new CryptoServerKeySpec(privateKeySpec);
        paramsImport.setExportable(allowExport);
        paramsImport.setPlainExportable(allowPlainExport);
        SecretKey privateJCE = kfJCE.generateSecret(paramsImport);

        privateKeySpecJCE = (SecretKeySpec) kfJCE.getKeySpec(privateJCE, SecretKeySpec.class);
        if (privateKeySpecJCE == null) {
            throw new Exception(alg + " key could not be exported");
        }

        if (!Arrays.equals(privateKeySpec.getEncoded(), privateKeySpecJCE.getEncoded())) {
            throw new Exception("The secret key is different");
        }
    }

    public static void unwrapWithExportFlag(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE - unwrapWithExportFlag ---\n");
        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(export_Flags.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            CryptoServerUnwrapAlgorithmParameterSpec paramUnwrap = new CryptoServerUnwrapAlgorithmParameterSpec(null);
            paramUnwrap.setExportable(true);
            paramUnwrap.setPlainExportable(false);
            testWrapUnwrap_AESWithRSA_with_CS_BC(provider, paramUnwrap);

            CryptoServerUnwrapAlgorithmParameterSpec paramUnwrap2 = new CryptoServerUnwrapAlgorithmParameterSpec(null);
            paramUnwrap2.setExportable(true);
            paramUnwrap2.setPlainExportable(true);
            testWrapUnwrap_AESWithRSA_with_CS_BC(provider, paramUnwrap2);

            CryptoServerUnwrapAlgorithmParameterSpec paramUnwrap3 = new CryptoServerUnwrapAlgorithmParameterSpec(null);
            paramUnwrap3.setExportable(false);
            paramUnwrap3.setPlainExportable(true);
            testWrapUnwrap_AESWithRSA_with_CS_BC(provider, paramUnwrap3);

            CryptoServerUnwrapAlgorithmParameterSpec paramUnwrap4 = new CryptoServerUnwrapAlgorithmParameterSpec(null);
            paramUnwrap4.setExportable(true);
            paramUnwrap4.setPlainExportable(true);
            testWrapUnwrap_RSAWithAES_with_CS_BC(provider, paramUnwrap4);

            CryptoServerUnwrapAlgorithmParameterSpec paramUnwrap5 = new CryptoServerUnwrapAlgorithmParameterSpec(null);
            paramUnwrap5.setExportable(true);
            paramUnwrap5.setPlainExportable(false);
            testWrapUnwrap_RSAWithAES_with_CS_BC(provider, paramUnwrap5);

            CryptoServerUnwrapAlgorithmParameterSpec paramUnwrap6 = new CryptoServerUnwrapAlgorithmParameterSpec(null);
            paramUnwrap6.setExportable(true);
            paramUnwrap6.setPlainExportable(false);
            testWrapUnwrap_RSAWithAES_with_CS_BC(provider, paramUnwrap6);

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

    private static void testWrapUnwrap_AESWithRSA_with_CS_BC(CryptoServerProvider cryptoServerProvider, CryptoServerUnwrapAlgorithmParameterSpec paramUnwrap) throws Exception {
        // Generate RSA key
        CryptoServerRSAKeyGenParameterSpec rsaParam = new CryptoServerRSAKeyGenParameterSpec(2048, new BigInteger("010001", 16));
        rsaParam.setExportable(true);
        rsaParam.setPlainExportable(true);
        Provider bouncyProvider = new BouncyCastleProvider();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", cryptoServerProvider);
        kpg.initialize(rsaParam, null);
        KeyPair keyPair = kpg.generateKeyPair();

        // export public key and private
        KeyFactory kf = KeyFactory.getInstance("RSA", cryptoServerProvider);
        RSAPublicKeySpec publicKeySpec = kf.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);

        // import key pair in bouncy
        KeyFactory kfBc = KeyFactory.getInstance("RSA", bouncyProvider);
        PublicKey publicBc = kfBc.generatePublic(publicKeySpec);

        // generate AES key in Bouncy to unwrap in CryptoServer
        System.out.println("generate AES key...");
        KeyGenerator kg = KeyGenerator.getInstance("AES", bouncyProvider);
        kg.init(128, null);
        SecretKey aesKey = kg.generateKey();

        // encrypt private key
        Cipher testCipher = Cipher.getInstance("RSA/None/PKCS1Padding", bouncyProvider);
        testCipher.init(Cipher.ENCRYPT_MODE, publicBc);
        byte[] aesWrapped = testCipher.doFinal(aesKey.getEncoded());

        // import (unwrap) encrypted AES key
        System.out.println("import (unwrap) encrypted AES key...");
        Cipher wrapCipher = Cipher.getInstance("RSA/None/PKCS1Padding", cryptoServerProvider);

        wrapCipher.init(Cipher.UNWRAP_MODE, keyPair.getPrivate(), paramUnwrap);
        CryptoServerSecretKey cpAesKey = (CryptoServerSecretKey) wrapCipher.unwrap(aesWrapped, "AES", Cipher.SECRET_KEY);

        // export (wrap) AES key (encrypted with RSA key)
        System.out.println("export (wrap) AES key (encrypted with RSA key)...");
        wrapCipher.init(Cipher.WRAP_MODE, keyPair.getPublic());
        byte[] wrappedKey = wrapCipher.wrap(cpAesKey);

        // decipher the wrapped key
        Cipher testDecipher = Cipher.getInstance("RSA/None/PKCS1Padding", cryptoServerProvider);
        testDecipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] aesClearWrapped = testDecipher.doFinal(wrappedKey);

        if (!Arrays.equals(aesClearWrapped, aesKey.getEncoded())) {
            throw new Exception("Calculated key (after unwrap+wrap) is different than the original key");
        }
    }

    private static void testWrapUnwrap_RSAWithAES_with_CS_BC(CryptoServerProvider cryptoServerProvider, CryptoServerUnwrapAlgorithmParameterSpec paramUnwrap) throws Exception {
        Provider bouncyProvider = new BouncyCastleProvider();
        // generate AES key in CryptoServer
        System.out.println("generate AES key...");

        CryptoServerKeyGenParameterSpec cryptoServerKeyGenParameterSpec =
                new CryptoServerKeyGenParameterSpec(256);
        cryptoServerKeyGenParameterSpec.setExportable(true);
        cryptoServerKeyGenParameterSpec.setPlainExportable(true);
        KeyGenerator kg = KeyGenerator.getInstance("AES", cryptoServerProvider);
        kg.init(cryptoServerKeyGenParameterSpec, null);
        SecretKey aesKey = kg.generateKey();

        SecretKeyFactory kf = SecretKeyFactory.getInstance("AES", cryptoServerProvider);
        SecretKeySpec secretKeySpec = (SecretKeySpec) kf.getKeySpec(aesKey, SecretKeySpec.class);

        SecretKeyFactory kfSecretBC = SecretKeyFactory.getInstance("AES", bouncyProvider);
        SecretKey aesKeyBC = kfSecretBC.generateSecret(secretKeySpec);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", bouncyProvider);
        kpg.initialize(2048, null);
        KeyPair keyPair = kpg.generateKeyPair();

        // encrypt private key
        Cipher testCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", bouncyProvider);
        testCipher.init(Cipher.ENCRYPT_MODE, aesKeyBC);
        byte[] privateWrapped = testCipher.doFinal(keyPair.getPrivate().getEncoded());

        // import (unwrap) encrypted AES key
        System.out.println("import (unwrap) encrypted RSA key...");
        Cipher wrapCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", cryptoServerProvider);

        wrapCipher.init(Cipher.UNWRAP_MODE, aesKey, paramUnwrap);
        CryptoServerRSAPrivateKey privateKeyImported = (CryptoServerRSAPrivateKey) wrapCipher.unwrap(privateWrapped, "RSA", Cipher.PRIVATE_KEY);

        // export (wrap) AES key
        System.out.println("export (wrap) RSA key (encrypted with AES key)...");
        wrapCipher.init(Cipher.WRAP_MODE, aesKey);
        byte[] wrappedKey = wrapCipher.wrap(privateKeyImported);

        // decipher the wrapped key
        Cipher testDecipher = Cipher.getInstance("AES/ECB/PKCS5Padding", cryptoServerProvider);
        testDecipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] privateClearWrapped = testDecipher.doFinal(wrappedKey);

        if (!Arrays.equals(privateClearWrapped, keyPair.getPrivate().getEncoded())) {
            throw new Exception("Calculated key (after unwrap+wrap) is different than the original key");
        }
    }

    public static <T extends KeySpec> void importPrivateKeyToCryptoServer(KeyPair keyPair, String algorithm, Provider sourceProvider, Provider targetProvider, Class<T> keySpecClass, boolean allowExport, boolean allowPlainExport) throws GeneralSecurityException {
        // Extract private key spec from original provider
        KeyFactory sourceKf = KeyFactory.getInstance(algorithm, sourceProvider);
        T privateKeySpec = sourceKf.getKeySpec(keyPair.getPrivate(), keySpecClass);

        // Import into CryptoServer
        KeyFactory targetKf = KeyFactory.getInstance(algorithm, targetProvider);
        CryptoServerKeySpec paramsImport = new CryptoServerKeySpec(privateKeySpec);
        paramsImport.setExportable(allowExport);
        paramsImport.setPlainExportable(allowPlainExport);

        PrivateKey privateJCE = targetKf.generatePrivate(paramsImport);

        // Export back to verify
        T exportedSpec = targetKf.getKeySpec(privateJCE, keySpecClass);

        if (exportedSpec == null) {
            throw new GeneralSecurityException("Private " + algorithm + " key could not be exported");
        }

        if (privateKeySpec instanceof ECPrivateKeySpec) {
            ECPrivateKeySpec ecOriginal = (ECPrivateKeySpec) privateKeySpec;
            ECPrivateKeySpec ecExported = (ECPrivateKeySpec) exportedSpec;

            if (ecOriginal.getS().compareTo(ecExported.getS()) != 0) {
                throw new GeneralSecurityException("The value S is different");
            }
        } else if (privateKeySpec instanceof RSAPrivateKeySpec) {
            RSAPrivateKeySpec rsaOriginal = (RSAPrivateKeySpec) privateKeySpec;
            RSAPrivateKeySpec rsaExported = (RSAPrivateKeySpec) exportedSpec;

            if (rsaOriginal.getPrivateExponent().compareTo(rsaExported.getPrivateExponent()) != 0) {
                throw new GeneralSecurityException("The private exponent is different");
            }

            if (rsaOriginal.getModulus().compareTo(rsaExported.getModulus()) != 0) {
                throw new GeneralSecurityException("The modulus is different");
            }
        }
    }
}
