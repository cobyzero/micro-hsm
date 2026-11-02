package defaults;

import CryptoServerJCE.*;

import java.util.*;
import java.security.*;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * Delete all keys
 */
public class key_Delete {
    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE: key_Delete ---\n");
        int nKeys = 0;

        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(key_Delete.class.getResourceAsStream("/CryptoServer.cfg"));

            // authenticate
            provider.loginPassword("JCE", "12345678");

            // open key store
            KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
            ks.load(null, null);
            System.out.println("KeyStore: " + ks.getType() + "\n");

            // list keys
            Enumeration<String> kl = ks.aliases();

            while (kl.hasMoreElements()) {
                String name = kl.nextElement();
                System.out.println("delete: " + name);
                ks.deleteEntry(name);
                nKeys++;
            }

            System.out.println("\n" + nKeys + " keys deleted");
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
}
