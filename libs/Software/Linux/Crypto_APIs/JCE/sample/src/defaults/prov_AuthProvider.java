package defaults;

import CryptoServerJCE.*;

import javax.crypto.*;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;

import java.security.*;

/**
 * This program demonstrates the usage of the Utimaco's JCE Provider
 * for the CryptoServer Hardware Security Module.
 * <p>
 * Login methods from AuthProvider
 */
public class prov_AuthProvider {
    public static SecretKey generateKey(Provider provider) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES", provider);
        CryptoServerKeyGenParameterSpec kgp = new CryptoServerKeyGenParameterSpec();
        kgp.setKeySize(256);
        kg.init(kgp, null);
        return kg.generateKey();
    }

    public static void main(String[] args) throws Exception {
        System.out.println("\n--- Utimaco CryptoServer JCE: prov_AuthProvider ---\n");
        CryptoServerProvider provider = null;

        try {
            // load provider
            provider = args.length > 0 ? new CryptoServerProvider(args[0]) : new CryptoServerProvider(prov_AuthProvider.class.getResourceAsStream("/CryptoServer.cfg"));

            System.out.println("\nLogin to CryptoServer...");
            char[] pwd = { '1', '2', '3', '4', '5', '6', '7', '8' };
            provider.login(null, new HSMCredentialsCallBackHandler("JCE", pwd));
            System.out.println("OK");

            System.out.println("\nGenerate key...");
            SecretKey key = generateKey(provider);
            System.out.println("OK");

            System.out.println("\nStore key in key store...");
            KeyStore ks = KeyStore.getInstance("CryptoServer", provider);
            ks.load(null, null);
            ks.setKeyEntry("TEST_KEY", key, null, null);
            System.out.println("OK");

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
    /*********************************************************************
     * 
     * An own "CallBackHandler" can be implemented to retrieve the HSM credentials
     * The user must be stored in a NameCallback
     * The password must be stored in a PasswordCallback
     *
     **********************************************************************/
    static class HSMCredentialsCallBackHandler implements CallbackHandler {

        private String user = null;
        private char[] password = null;

        public HSMCredentialsCallBackHandler(String userHSM, char[] passwordHSM) {
            user = userHSM;
            password = passwordHSM;
        }

        @Override
        public void handle(Callback[] callbacks) {
            for (Callback callback : callbacks) {
                if (callback instanceof PasswordCallback) {
                    PasswordCallback pc = (PasswordCallback) callback;
                    pc.setPassword(password);
                } else if (callback instanceof NameCallback) {
                    NameCallback nc = (NameCallback) callback;
                    nc.setName(user);
                }
            }
        }
    }
}
