package defaults;

import CryptoServerJCE.*;

import javax.crypto.*;
import java.security.*;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * Login methods
 */
public class prov_Login {
    public static SecretKey generateKey(Provider provider) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES", provider);
        CryptoServerKeyGenParameterSpec kgp = new CryptoServerKeyGenParameterSpec();
        kgp.setKeySize(256);
        kg.init(kgp, null);
        return kg.generateKey();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE: prov_Login ---\n");
        String providerName = null;
        Provider provider = null;

        if (args.length > 1) {
            providerName = args[1];
        }

        printProviders();

        try {
            if (providerName == null) {
                // load provider
                provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(prov_Login.class.getResourceAsStream("/CryptoServer.cfg"));

                loginToProvider(provider);

                System.out.println("\nGenerate key...");
                SecretKey key = generateKey(provider);
                System.out.println("OK");

                System.out.println("\nStore key in key store...");
                KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
                ks.load(null, null);
                ks.setKeyEntry("TEST_KEY", key, null, null);
                System.out.println("OK");
            } else {
                provider = Security.getProvider(providerName);

                if (provider == null) {
                    throw new Exception("Invalid provider: " + providerName);
                }

                if (provider.getName().equals("CryptoServer")) {
                    // load key store (implies authentication of default user)
                    System.out.println("\nAccessing key store...");
                    KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
                    ks.load(null, "12345678".toCharArray());
                }
            }
        } catch (Exception ex) {
            throw ex;
        } finally {
            // close
            if (provider != null && provider instanceof CryptoServerProvider) {
                ((CryptoServerProvider) provider).close();
            }
        }

        System.out.println("Done");
    }

    private static void printProviders() {
        Provider[] providers = Security.getProviders();
        System.out.println("List of all Providers:");
        for (Provider p : providers) {
            System.out.println("  " + p.getName());
        }
    }

    private static void loginToProvider(Provider provider) throws Exception {
        System.out.println("\nLogin to CryptoServer...");

        CryptoServerProvider cs = (CryptoServerProvider) provider;
        switch (1) {
            case 1:
                cs.loginPassword("JCE", "12345678");
                break;
            case 2:
                cs.loginSign("JCE_RSA", "rsa.key", null);
                break;
            case 3:
                cs.loginSign("JCE_RSA", "rsa_enc.key", "utimaco");
                break;
        }

        System.out.println("OK");
    }
}
