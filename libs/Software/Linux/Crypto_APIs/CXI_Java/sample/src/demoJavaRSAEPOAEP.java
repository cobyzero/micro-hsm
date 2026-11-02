import CryptoServerCXI.*;
import CryptoServerAPI.*;
import java.util.Arrays;


/**
 * This program illustrates the usage of the CryptoServerCXI API for the CryptoServer Hardware Security Module.
 *
 * RSAEP-OAEP 
 * - Exports AES256 Key wrapped with RSA 2048 with OAEP padding
 * - Imports to AES256 Key
 * - Verifies via decryption of byte array.
 *
 * @note In favor of better understandability exception handling has been removed to a minimum.
 */
public class demoJavaRSAEPOAEP
{
  static CryptoServerCXI cxi = null;
  static String group = "test";    

  public static void main(String[] args) throws Exception 
  {
    System.out.format("\n--- Utimaco CryptoServer CXI Demo - RSAEP-OAEP ---\n");    
        
    String device = System.getenv("CRYPTOSERVER");
    
    if (device == null)
    {      
      device = "3001@127.0.0.1"; // address of simulator
      //device = "PCI:0";
      //device = "192.168.4.183";
    }
    
    try
    {    
        // create instance of CryptoServerCXI (opens connection to CryptoServer)
        cxi = new CryptoServerCXI(device, 3000);
        cxi.setTimeout(60000);

        System.out.format("device: " + cxi.getDevice() + "\n");

        // logon
        cxi.logon("CXI_HMAC", "", "12345678".getBytes());

        /* exporting and importing AES key blob with Java CXI 
           using RSA as wrapping key and OAEP/SHA256.
           example won't work in FIPS mode due to usage and key length restrictions
        */

        // generate an AES key
        CryptoServerCXI.KeyAttributes attr_aes = new CryptoServerCXI.KeyAttributes();
        attr_aes.setAlgo(CryptoServerCXI.KEY_ALGO_AES);
        attr_aes.setSize(256);     
        attr_aes.setName("CXI_AES_KEY");
        attr_aes.setGroup("test");
        attr_aes.setExport(1); // key export allowed
        CryptoServerCXI.Key aes_key = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr_aes, 0);
        CryptoServerUtil.xtrace("aesKey handle", aes_key.getEncoded());

        // generate an RSA wrapping key
        CryptoServerCXI.KeyAttributes attr_wrap_rsa = new CryptoServerCXI.KeyAttributes();
        attr_wrap_rsa.setAlgo(CryptoServerCXI.KEY_ALGO_RSA);
        attr_wrap_rsa.setSize(2048);     
        attr_wrap_rsa.setName("CXI_RSA_KEY");
        attr_wrap_rsa.setGroup("test");      
        CryptoServerCXI.Key rsa_wrap_key = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr_wrap_rsa, 0);
        CryptoServerUtil.xtrace("rsaWrapKey handle", rsa_wrap_key.getEncoded());

        // encrypt data in CBC mode
        String text = "Oh, say can you see by the dawn's early light\n"
                    + "What so proudly we hailed at the twilights last gleaming?\n"
                    + "Whose broad stripes and broght stars thru the perilous fight,\n"
                    + "O'er the ramparts we watched were so gallantly streaming?\n"
                    + "And the rocket's red glare, the bombs bursting in air,\n"
                    + "Gave proof through the night that our flag was still there.\n"
                    + "Oh, say does that star-spangled banner yet wave\n"
                    + "O'er the land of the free and the home of the brave?\n";

        byte [] data = text.getBytes();
        byte [] crypto = new byte[0];
        int mech = CryptoServerCXI.MECH_MODE_ENCRYPT | CryptoServerCXI.MECH_CHAIN_CBC | CryptoServerCXI.MECH_PAD_PKCS5;

        crypto = cxi.crypt(aes_key, mech, null, data, null);

        // export key using RSA / OAEP / SHA256
        //  the last optional param to set non-default padding/hash 
        byte [] key_blob = cxi.exportKey(aes_key, CryptoServerCXI.KEY_TYPE_SECRET, rsa_wrap_key, CryptoServerCXI.MECH_PAD_OAEP | CryptoServerCXI.MECH_HASH_ALGO_SHA256);      
        CryptoServerUtil.xtrace("Export keyBlob", key_blob);

        // generate attributes for AES Import key
        CryptoServerCXI.KeyAttributes attr_aes_import = new CryptoServerCXI.KeyAttributes();
        attr_aes_import.setAlgo(CryptoServerCXI.KEY_ALGO_AES);
        attr_aes_import.setSize(256);     
        attr_aes_import.setName("CXI_AES_KEY_Import");
        attr_aes_import.setGroup("test");
        attr_aes_import.setExport(1); // key export allowed

        // import key (using same padding/hashing) over the top of the same AES key with the newly generated key_blob
        // the last optional param to set non-default padding/hash
        cxi.importKey(CryptoServerCXI.FLAG_OVERWRITE, CryptoServerCXI.KEY_TYPE_SECRET, attr_aes_import, key_blob, rsa_wrap_key, CryptoServerCXI.MECH_PAD_OAEP | CryptoServerCXI.MECH_HASH_ALGO_SHA256);    	    

        // Go get handle to imported key
        CryptoServerCXI.Key aes_key_import = cxi.findKey(attr_aes_import);
        CryptoServerUtil.xtrace("imported aesKey handle", aes_key.getEncoded());

        // decrypt data (in one shot) with imported key      
        mech = CryptoServerCXI.MECH_MODE_DECRYPT | CryptoServerCXI.MECH_CHAIN_CBC | CryptoServerCXI.MECH_PAD_PKCS5;
        byte [] plain = cxi.crypt(aes_key_import, mech, null, crypto, null);

        System.out.format("Plain Data:\n" + new String(plain));

        // compare result
        if (Arrays.equals(plain, data))
        {
            System.out.format("\nResults are equal, export / import succeeded\n");
        }
        else
        {
            CryptoServerUtil.xtrace("data", data);
            CryptoServerUtil.xtrace("encrypted data", crypto);
            CryptoServerUtil.xtrace("decrypted data", plain);
            throw new CryptoServerException(-1, "decrypted data doesn't match original data");
        }
    }
    finally
    {
        System.out.format("\nclosing connection\n");
        if (cxi != null)
        {
            cxi.logoff();
            cxi.close();
        }
    }

    System.out.format("Done\n");
    }
  }

