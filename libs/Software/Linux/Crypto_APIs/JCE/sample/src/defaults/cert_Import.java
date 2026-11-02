package defaults;
import CryptoServerJCE.*;
import CryptoServerAPI.*;
import java.io.*;
import java.util.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.security.spec.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.math.BigInteger;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 *
 * Certificate import
 *
 */
public class cert_Import {
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

    private static final byte[] TestCertificate =
        {
            (byte) 0x30, (byte) 0x82, (byte) 0x03, (byte) 0x7B, (byte) 0x30, (byte) 0x82, (byte) 0x02, (byte) 0x63, (byte) 0xA0, (byte) 0x03, (byte) 0x02, (byte) 0x01,
            (byte) 0x02, (byte) 0x02, (byte) 0x01, (byte) 0x01, (byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0x86,
            (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x00, (byte) 0x30, (byte) 0x37, (byte) 0x31, (byte) 0x16, (byte) 0x30,
            (byte) 0x14, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x0D, (byte) 0x4F, (byte) 0x53, (byte) 0x53, (byte) 0x4C,
            (byte) 0x20, (byte) 0x52, (byte) 0x53, (byte) 0x41, (byte) 0x20, (byte) 0x52, (byte) 0x6F, (byte) 0x6F, (byte) 0x74, (byte) 0x31, (byte) 0x0B, (byte) 0x30,
            (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x44, (byte) 0x45, (byte) 0x31, (byte) 0x10,
            (byte) 0x30, (byte) 0x0E, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0A, (byte) 0x13, (byte) 0x07, (byte) 0x55, (byte) 0x74, (byte) 0x69,
            (byte) 0x6D, (byte) 0x61, (byte) 0x63, (byte) 0x6F, (byte) 0x30, (byte) 0x1E, (byte) 0x17, (byte) 0x0D, (byte) 0x30, (byte) 0x38, (byte) 0x30, (byte) 0x31,
            (byte) 0x31, (byte) 0x34, (byte) 0x30, (byte) 0x39, (byte) 0x35, (byte) 0x39, (byte) 0x31, (byte) 0x35, (byte) 0x5A, (byte) 0x17, (byte) 0x0D, (byte) 0x31,
            (byte) 0x38, (byte) 0x30, (byte) 0x31, (byte) 0x31, (byte) 0x31, (byte) 0x30, (byte) 0x39, (byte) 0x35, (byte) 0x39, (byte) 0x31, (byte) 0x35, (byte) 0x5A,
            (byte) 0x30, (byte) 0x37, (byte) 0x31, (byte) 0x16, (byte) 0x30, (byte) 0x14, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13,
            (byte) 0x0D, (byte) 0x4F, (byte) 0x53, (byte) 0x53, (byte) 0x4C, (byte) 0x20, (byte) 0x52, (byte) 0x53, (byte) 0x41, (byte) 0x20, (byte) 0x52, (byte) 0x6F,
            (byte) 0x6F, (byte) 0x74, (byte) 0x31, (byte) 0x0B, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13,
            (byte) 0x02, (byte) 0x44, (byte) 0x45, (byte) 0x31, (byte) 0x10, (byte) 0x30, (byte) 0x0E, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0A,
            (byte) 0x13, (byte) 0x07, (byte) 0x55, (byte) 0x74, (byte) 0x69, (byte) 0x6D, (byte) 0x61, (byte) 0x63, (byte) 0x6F, (byte) 0x30, (byte) 0x82, (byte) 0x01,
            (byte) 0x22, (byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x01,
            (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x82, (byte) 0x01, (byte) 0x0F, (byte) 0x00, (byte) 0x30, (byte) 0x82, (byte) 0x01,
            (byte) 0x0A, (byte) 0x02, (byte) 0x82, (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0xD3, (byte) 0xCB, (byte) 0x58, (byte) 0x5A, (byte) 0xB2, (byte) 0x40,
            (byte) 0xF5, (byte) 0xBA, (byte) 0xD6, (byte) 0x23, (byte) 0x38, (byte) 0xCA, (byte) 0x89, (byte) 0x03, (byte) 0x0A, (byte) 0x16, (byte) 0x9B, (byte) 0x08,
            (byte) 0x0E, (byte) 0x39, (byte) 0x38, (byte) 0x4D, (byte) 0xB3, (byte) 0xF5, (byte) 0x83, (byte) 0x06, (byte) 0x6E, (byte) 0xC3, (byte) 0xF2, (byte) 0xB8,
            (byte) 0x70, (byte) 0x5E, (byte) 0x50, (byte) 0xD3, (byte) 0x42, (byte) 0x62, (byte) 0xE1, (byte) 0x10, (byte) 0x90, (byte) 0x95, (byte) 0x12, (byte) 0x92,
            (byte) 0x16, (byte) 0xC3, (byte) 0x99, (byte) 0x79, (byte) 0x9B, (byte) 0x0D, (byte) 0x59, (byte) 0x8C, (byte) 0x49, (byte) 0xCB, (byte) 0xBD, (byte) 0xCE,
            (byte) 0x83, (byte) 0xDE, (byte) 0x54, (byte) 0x3D, (byte) 0xC1, (byte) 0xC0, (byte) 0x26, (byte) 0xC8, (byte) 0xBB, (byte) 0x60, (byte) 0xB7, (byte) 0x9F,
            (byte) 0xCE, (byte) 0xB7, (byte) 0x10, (byte) 0xC8, (byte) 0x99, (byte) 0xB6, (byte) 0x44, (byte) 0xCF, (byte) 0x12, (byte) 0x57, (byte) 0x1C, (byte) 0x71,
            (byte) 0x3E, (byte) 0x73, (byte) 0x5B, (byte) 0x6B, (byte) 0x2A, (byte) 0xC3, (byte) 0x48, (byte) 0x6B, (byte) 0xB8, (byte) 0xEB, (byte) 0x5B, (byte) 0x5F,
            (byte) 0x87, (byte) 0xE2, (byte) 0x13, (byte) 0x08, (byte) 0x88, (byte) 0xC0, (byte) 0x01, (byte) 0x3A, (byte) 0x97, (byte) 0xD5, (byte) 0xEA, (byte) 0x62,
            (byte) 0x46, (byte) 0xFE, (byte) 0x4D, (byte) 0x14, (byte) 0x96, (byte) 0xF0, (byte) 0x01, (byte) 0xC0, (byte) 0x47, (byte) 0xBB, (byte) 0xF4, (byte) 0xA1,
            (byte) 0x62, (byte) 0x3E, (byte) 0x4E, (byte) 0x4F, (byte) 0xC3, (byte) 0x42, (byte) 0xC6, (byte) 0x42, (byte) 0x67, (byte) 0x51, (byte) 0x8F, (byte) 0x2C,
            (byte) 0xFD, (byte) 0x20, (byte) 0x19, (byte) 0x82, (byte) 0x52, (byte) 0x87, (byte) 0x2B, (byte) 0xFF, (byte) 0xE1, (byte) 0x81, (byte) 0xBC, (byte) 0xB6,
            (byte) 0xF0, (byte) 0x97, (byte) 0x54, (byte) 0x4D, (byte) 0x49, (byte) 0x2D, (byte) 0x33, (byte) 0xCD, (byte) 0xFD, (byte) 0x21, (byte) 0xBF, (byte) 0x88,
            (byte) 0x01, (byte) 0xC8, (byte) 0x80, (byte) 0xDD, (byte) 0x73, (byte) 0x34, (byte) 0x77, (byte) 0x17, (byte) 0xE5, (byte) 0x8D, (byte) 0xC4, (byte) 0xD8,
            (byte) 0x1B, (byte) 0xA5, (byte) 0xE6, (byte) 0x7D, (byte) 0x27, (byte) 0x74, (byte) 0xA6, (byte) 0x1F, (byte) 0x6E, (byte) 0x6C, (byte) 0x93, (byte) 0xA5,
            (byte) 0xCA, (byte) 0xA0, (byte) 0xD6, (byte) 0xD7, (byte) 0x61, (byte) 0x7C, (byte) 0xD7, (byte) 0x90, (byte) 0x5C, (byte) 0xCD, (byte) 0x4B, (byte) 0x63,
            (byte) 0x88, (byte) 0x43, (byte) 0x68, (byte) 0xEC, (byte) 0xB1, (byte) 0x3C, (byte) 0x77, (byte) 0x2A, (byte) 0x46, (byte) 0xE5, (byte) 0x16, (byte) 0x3B,
            (byte) 0xFF, (byte) 0x19, (byte) 0xC6, (byte) 0x49, (byte) 0x65, (byte) 0x4F, (byte) 0x20, (byte) 0x7D, (byte) 0x67, (byte) 0xF7, (byte) 0x48, (byte) 0x32,
            (byte) 0x74, (byte) 0x1F, (byte) 0x52, (byte) 0xF6, (byte) 0xEC, (byte) 0xA6, (byte) 0x6F, (byte) 0x63, (byte) 0xEB, (byte) 0x17, (byte) 0xAC, (byte) 0x3B,
            (byte) 0x4F, (byte) 0x8F, (byte) 0xC8, (byte) 0x83, (byte) 0x68, (byte) 0x76, (byte) 0x0F, (byte) 0xE1, (byte) 0xA9, (byte) 0xF4, (byte) 0xAC, (byte) 0x53,
            (byte) 0x3B, (byte) 0x56, (byte) 0xDA, (byte) 0xB2, (byte) 0x1C, (byte) 0x01, (byte) 0xDA, (byte) 0xB4, (byte) 0x54, (byte) 0xE2, (byte) 0x7D, (byte) 0xD5,
            (byte) 0xDF, (byte) 0xCB, (byte) 0xED, (byte) 0xC7, (byte) 0xE8, (byte) 0xD3, (byte) 0xD6, (byte) 0xBA, (byte) 0x44, (byte) 0x31, (byte) 0x02, (byte) 0x03,
            (byte) 0x01, (byte) 0x00, (byte) 0x01, (byte) 0xA3, (byte) 0x81, (byte) 0x91, (byte) 0x30, (byte) 0x81, (byte) 0x8E, (byte) 0x30, (byte) 0x1D, (byte) 0x06,
            (byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x0E, (byte) 0x04, (byte) 0x16, (byte) 0x04, (byte) 0x14, (byte) 0xCC, (byte) 0x70, (byte) 0x10, (byte) 0x8F,
            (byte) 0xF7, (byte) 0x38, (byte) 0x3E, (byte) 0xAC, (byte) 0x09, (byte) 0x6A, (byte) 0x5F, (byte) 0xE4, (byte) 0x0F, (byte) 0xE7, (byte) 0x05, (byte) 0x6E,
            (byte) 0x06, (byte) 0x79, (byte) 0x36, (byte) 0x62, (byte) 0x30, (byte) 0x5F, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x23, (byte) 0x04,
            (byte) 0x58, (byte) 0x30, (byte) 0x56, (byte) 0x80, (byte) 0x14, (byte) 0xCC, (byte) 0x70, (byte) 0x10, (byte) 0x8F, (byte) 0xF7, (byte) 0x38, (byte) 0x3E,
            (byte) 0xAC, (byte) 0x09, (byte) 0x6A, (byte) 0x5F, (byte) 0xE4, (byte) 0x0F, (byte) 0xE7, (byte) 0x05, (byte) 0x6E, (byte) 0x06, (byte) 0x79, (byte) 0x36,
            (byte) 0x62, (byte) 0xA1, (byte) 0x3B, (byte) 0xA4, (byte) 0x39, (byte) 0x30, (byte) 0x37, (byte) 0x31, (byte) 0x16, (byte) 0x30, (byte) 0x14, (byte) 0x06,
            (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x03, (byte) 0x13, (byte) 0x0D, (byte) 0x4F, (byte) 0x53, (byte) 0x53, (byte) 0x4C, (byte) 0x20, (byte) 0x52,
            (byte) 0x53, (byte) 0x41, (byte) 0x20, (byte) 0x52, (byte) 0x6F, (byte) 0x6F, (byte) 0x74, (byte) 0x31, (byte) 0x0B, (byte) 0x30, (byte) 0x09, (byte) 0x06,
            (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x06, (byte) 0x13, (byte) 0x02, (byte) 0x44, (byte) 0x45, (byte) 0x31, (byte) 0x10, (byte) 0x30, (byte) 0x0E,
            (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x04, (byte) 0x0A, (byte) 0x13, (byte) 0x07, (byte) 0x55, (byte) 0x74, (byte) 0x69, (byte) 0x6D, (byte) 0x61,
            (byte) 0x63, (byte) 0x6F, (byte) 0x82, (byte) 0x01, (byte) 0x01, (byte) 0x30, (byte) 0x0C, (byte) 0x06, (byte) 0x03, (byte) 0x55, (byte) 0x1D, (byte) 0x13,
            (byte) 0x04, (byte) 0x05, (byte) 0x30, (byte) 0x03, (byte) 0x01, (byte) 0x01, (byte) 0xFF, (byte) 0x30, (byte) 0x0D, (byte) 0x06, (byte) 0x09, (byte) 0x2A,
            (byte) 0x86, (byte) 0x48, (byte) 0x86, (byte) 0xF7, (byte) 0x0D, (byte) 0x01, (byte) 0x01, (byte) 0x05, (byte) 0x05, (byte) 0x00, (byte) 0x03, (byte) 0x82,
            (byte) 0x01, (byte) 0x01, (byte) 0x00, (byte) 0x37, (byte) 0x33, (byte) 0xF5, (byte) 0x2E, (byte) 0x6C, (byte) 0x5B, (byte) 0x2E, (byte) 0xBF, (byte) 0x84,
            (byte) 0xD0, (byte) 0xF1, (byte) 0xF0, (byte) 0xDF, (byte) 0xF7, (byte) 0x62, (byte) 0xF6, (byte) 0x81, (byte) 0x88, (byte) 0x3E, (byte) 0x22, (byte) 0xD5,
            (byte) 0x99, (byte) 0xE8, (byte) 0x8B, (byte) 0x20, (byte) 0x94, (byte) 0xD4, (byte) 0x76, (byte) 0xF8, (byte) 0x2C, (byte) 0x0B, (byte) 0xB6, (byte) 0x9F,
            (byte) 0xAC, (byte) 0x4D, (byte) 0x96, (byte) 0x69, (byte) 0x9B, (byte) 0xDB, (byte) 0x27, (byte) 0x1E, (byte) 0xA8, (byte) 0x99, (byte) 0x68, (byte) 0x08,
            (byte) 0x1E, (byte) 0x5D, (byte) 0x32, (byte) 0x13, (byte) 0x63, (byte) 0xAA, (byte) 0x87, (byte) 0xCE, (byte) 0xA1, (byte) 0xFF, (byte) 0x4C, (byte) 0x84,
            (byte) 0xC1, (byte) 0x76, (byte) 0x72, (byte) 0xB7, (byte) 0x09, (byte) 0x04, (byte) 0x37, (byte) 0x7B, (byte) 0xBB, (byte) 0xD5, (byte) 0xF4, (byte) 0x07,
            (byte) 0xB0, (byte) 0x9A, (byte) 0x78, (byte) 0x8E, (byte) 0x37, (byte) 0xE2, (byte) 0x64, (byte) 0xA0, (byte) 0xE9, (byte) 0xB2, (byte) 0x78, (byte) 0xE8,
            (byte) 0xF3, (byte) 0x7D, (byte) 0x03, (byte) 0x28, (byte) 0xCB, (byte) 0xE5, (byte) 0xAF, (byte) 0xF9, (byte) 0xC8, (byte) 0xE2, (byte) 0x08, (byte) 0xDF,
            (byte) 0xD4, (byte) 0x52, (byte) 0x57, (byte) 0xD6, (byte) 0xA0, (byte) 0x44, (byte) 0xA3, (byte) 0x7A, (byte) 0xA6, (byte) 0x4B, (byte) 0x99, (byte) 0x05,
            (byte) 0xC0, (byte) 0x17, (byte) 0xA1, (byte) 0x8F, (byte) 0xF5, (byte) 0xAD, (byte) 0x49, (byte) 0x56, (byte) 0x84, (byte) 0x7D, (byte) 0xDE, (byte) 0x1E,
            (byte) 0x9B, (byte) 0xC6, (byte) 0xB3, (byte) 0x3E, (byte) 0x66, (byte) 0x8D, (byte) 0x03, (byte) 0x62, (byte) 0x9A, (byte) 0x39, (byte) 0x36, (byte) 0x65,
            (byte) 0xC5, (byte) 0x88, (byte) 0x9D, (byte) 0x9C, (byte) 0x53, (byte) 0x56, (byte) 0xF7, (byte) 0x35, (byte) 0x8E, (byte) 0x6D, (byte) 0x9A, (byte) 0xA3,
            (byte) 0x0D, (byte) 0x88, (byte) 0xB3, (byte) 0x2B, (byte) 0x62, (byte) 0xB2, (byte) 0xEE, (byte) 0x40, (byte) 0xC1, (byte) 0x25, (byte) 0xD8, (byte) 0xAF,
            (byte) 0x1E, (byte) 0x57, (byte) 0x82, (byte) 0x35, (byte) 0xB0, (byte) 0x48, (byte) 0x63, (byte) 0x78, (byte) 0xB6, (byte) 0x52, (byte) 0xDE, (byte) 0x15,
            (byte) 0x30, (byte) 0xA5, (byte) 0xA6, (byte) 0x6E, (byte) 0x23, (byte) 0x77, (byte) 0xA5, (byte) 0xD3, (byte) 0x09, (byte) 0xB0, (byte) 0xF5, (byte) 0x74,
            (byte) 0x5F, (byte) 0xCF, (byte) 0x64, (byte) 0x0D, (byte) 0xF8, (byte) 0x5A, (byte) 0x76, (byte) 0x7C, (byte) 0x59, (byte) 0x60, (byte) 0xA4, (byte) 0xE3,
            (byte) 0xBD, (byte) 0x90, (byte) 0xB1, (byte) 0x98, (byte) 0x0D, (byte) 0x03, (byte) 0xED, (byte) 0xC1, (byte) 0xBF, (byte) 0x47, (byte) 0x26, (byte) 0x0F,
            (byte) 0x7F, (byte) 0x78, (byte) 0x3F, (byte) 0x2E, (byte) 0x90, (byte) 0xB3, (byte) 0xE8, (byte) 0x38, (byte) 0xCC, (byte) 0xBB, (byte) 0xF0, (byte) 0xDB,
            (byte) 0xB6, (byte) 0xDC, (byte) 0xD4, (byte) 0x93, (byte) 0x3E, (byte) 0x80, (byte) 0x5A, (byte) 0x7A, (byte) 0xCB, (byte) 0x28, (byte) 0xF9, (byte) 0xF2,
            (byte) 0xAB, (byte) 0x67, (byte) 0x98, (byte) 0x36, (byte) 0xDD, (byte) 0xC0, (byte) 0xE9, (byte) 0x1E, (byte) 0x9D, (byte) 0x30, (byte) 0x00, (byte) 0x4D,
            (byte) 0x06, (byte) 0xFC, (byte) 0x65, (byte) 0x90, (byte) 0xF8, (byte) 0xE4, (byte) 0x3E, (byte) 0xA1, (byte) 0x80, (byte) 0x4B, (byte) 0xD6, (byte) 0x67,
            (byte) 0xBA, (byte) 0x40, (byte) 0x0D, (byte) 0xA9, (byte) 0x27, (byte) 0x9A, (byte) 0x50};

    // ********************************************************************************
    // main
    // ********************************************************************************
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE: key_Certificate ---\n");
        String rsaPrivateKeyName = "RSA_prv_cert_1";
        String rsaPublicKeyName = "RSA_pub_cert_1";

        CryptoServerProvider provider = null;

        try {
            if (Security.getProvider("BC") == null) {
                Security.addProvider(new BouncyCastleProvider());
            }

            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(cert_Import.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            // open key store
            KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
            ks.load(null, null);

            importCertificate(ks, rsaPublicKeyName);

            printCertificateChain(ks, rsaPublicKeyName);

            importPrivateKey(provider, ks, rsaPrivateKeyName);
            loadPrivateKey(ks, rsaPrivateKeyName);

            listKeyStoreEntries(ks);
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

    private static void listKeyStoreEntries(KeyStore ks) throws KeyStoreException {
        // list keys
        Enumeration<String> kl = ks.aliases();

        System.out.println(String.format("%-12s %-20s %s", "type", "name", "creation date"));
        System.out.println("----------------------------------------------------------------------");

        while (kl.hasMoreElements()) {
            String name = kl.nextElement();
            Date date = ks.getCreationDate(name);
            String type;

            if (ks.isKeyEntry(name)) {
                type = "Key";
            } else if (ks.isCertificateEntry(name)) {
                type = "Certificate";
            } else {
                type = "???";
            }

            System.out.println(String.format("%-12s %-20s %s", type, name, date));
        }
    }

    private static void loadPrivateKey(KeyStore ks, String rsaPrivateKeyName) throws Exception {
        PrivateKey privateKey;

        // load private key
        System.out.println("load private RSA key...");

        privateKey = (PrivateKey) ks.getKey(rsaPrivateKeyName, null);
        if (privateKey == null) {
            throw new Exception("key not found");
        }
    }

    private static void importPrivateKey(CryptoServerProvider provider, KeyStore ks, String rsaPrivateKeyName) throws Exception {
        // ...import private RSA key into key store
        System.out.println("import private RSA key...");

        PrivateKey privateKey = (PrivateKey) RSATestKey.getPrivateCRTKey(provider);
        PublicKey publicKey = (PublicKey) RSATestKey.getPublicKey(provider);
        DumyCertificate[] dummyChain = new DumyCertificate[] {provider.createSelfSignedDumyCertificate("Utimaco JCE Provider", publicKey, privateKey)};

        // Verification with Bouncy of the self-signed
        PublicKey publicKeySoftware = KeyFactory.getInstance(publicKey.getAlgorithm(), "BC").generatePublic(new X509EncodedKeySpec(publicKey.getEncoded()));
        ByteArrayInputStream inCertificate = new ByteArrayInputStream(dummyChain[0].getEncoded());
        Certificate certificateToCheck = CertificateFactory.getInstance("X.509", "BC").generateCertificate(inCertificate);
        certificateToCheck.verify(publicKeySoftware);

        ks.setKeyEntry(rsaPrivateKeyName, (Key) privateKey, null, dummyChain);
    }

    private static void printCertificateChain(KeyStore ks, String rsaPublicKeyName) throws Exception {
        // get certificate chain
        System.out.println("get certificate chain...");

        Certificate[] chain = ks.getCertificateChain(rsaPublicKeyName);
        if (chain == null) {
            throw new Exception("certificate chain not found");
        }

        for (int i = 0; i < chain.length; i++) {
            CryptoServerUtil.xtrace("cert[" + i + "]", chain[i].getEncoded());
        }
    }

    private static void importCertificate(KeyStore ks, String rsaPublicKeyName) throws Exception {
        // ...import certificate into key store
        System.out.println("import certificate...");

        X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(TestCertificate));

        ks.setCertificateEntry(rsaPublicKeyName, cert);

        // get certificate
        cert = (X509Certificate) ks.getCertificate(rsaPublicKeyName);
        if (cert == null) {
            throw new Exception("certificate not found");
        }

        CryptoServerUtil.xtrace("cert", cert.getEncoded());
    }
}
