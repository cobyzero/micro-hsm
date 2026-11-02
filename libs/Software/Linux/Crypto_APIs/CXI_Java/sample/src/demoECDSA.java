import CryptoServerAPI.*;
import CryptoServerCXI.*;

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.math.BigInteger;

/**
 * This program illustrates the usage of the CryptoServerCXI API for the CryptoServer Hardware Security Module.
 *
 * ECDSA
 *
 * @note In favour of better understandability exception handling has been removed to a minimum.
 */
public class demoECDSA
{
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer CXI Demo ---\n");    
        
    String device = System.getenv("CRYPTOSERVER");
    
    if (device == null)
    {      
      device = "3001@127.0.0.1"; // address of simulator
      //device = "PCI:0";
      //device = "192.168.4.183";
    }
    
    CryptoServerCXI cxi = null;
    String group = "test1";    
        
    try
    {    
      // create instance of CryptoServerCXI (opens connection to CryptoServer)
      cxi = new CryptoServerCXI(device, 3000);
      cxi.setTimeout(60000);
      
      System.out.println("device: " + cxi.getDevice());
      
      // logon
      cxi.logon("CXI_HMAC", "", "12345678".getBytes());
      
      // generate ECDSA key
      System.out.println("generate ECDSA key...");
      CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_ECDSA);
      attr.setSize(0);
      attr.setCurve("NIST-P256");      
      attr.setName("ECC_DEMO_KEY");
      attr.setGroup(group);
      
      CryptoServerCXI.Key ecKey = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr);
      
      // create random test data to be signed
      byte [] data = cxi.generateRandom(256, CryptoServerCXI.MECH_RND_PSEUDO);
      
      // compute hash 
      MessageDigest md = MessageDigest.getInstance("SHA1");
      md.update(data);
      byte [] hash = md.digest();
      
      // sign hash
      System.out.println("sign hash...");      
      byte [] sign = cxi.sign(ecKey, 0, hash);
      CryptoServerUtil.xtrace("signature", sign);
      
      // verify
      System.out.println("\nECDSA verify signature...");
      boolean result = cxi.verify(ecKey, 0, hash, sign);
      if (result != true)
        throw new CryptoServerException(-1, "signature verification failed");
           
      // mainpulate signature      
      System.out.println("verify manipulated signature...");
      sign[5] += 1;
      result = cxi.verify(ecKey, 0, hash, sign);
      
      if (result == true)
        throw new CryptoServerException(-1, "verification of manipulated signature succeded (?)");            
      
      // encrypt data (ECIES)      
      System.out.println("\nencrypt data (ECIES)...");
      int hashAlgo = CryptoServerCXI.MECH_HASH_ALGO_SHA256;      
      int cryptAlgo = CryptoServerCXI.KEY_ALGO_AES;
      int cryptMech = CryptoServerCXI.MECH_CHAIN_CBC;
      int cryptLength = 256;            
      int macAlgo = CryptoServerCXI.KEY_ALGO_RAW;
      int macMech = CryptoServerCXI.MECH_MODE_HMAC | CryptoServerCXI.MECH_HASH_ALGO_SHA256;
      int macLength = 0;
      /* alternatively use AES also for MAC creation 
      int macAlgo = CryptoServerCXI.KEY_ALGO_AES;
      int macMech = CryptoServerCXI.MECH_CHAIN_CBC;
      int macLength = 256;            
      */      
      
      CryptoServerCXI.MechParamECIES mechParam = new CryptoServerCXI.MechParamECIES(
        hashAlgo, cryptAlgo, cryptMech, cryptLength, macAlgo, macMech, macLength, null, null);
            
      data = "Yes we can!     ".getBytes();  // length has to be multiple of 16 bytes
      byte [] crypt = cxi.crypt(ecKey, CryptoServerCXI.MECH_MODE_ENCRYPT, mechParam.getEncoded(), data, null);
      
      // decrypt data (ECIES) 
      System.out.println("\ndecrypt data (ECIES)...");
      byte [] plain = cxi.crypt(ecKey, CryptoServerCXI.MECH_MODE_DECRYPT, mechParam.getEncoded(), crypt, null);
      CryptoServerUtil.xtrace("decrypted data", plain);
      
    }    
    finally
    {
      System.out.println("closing connection");            
      if (cxi != null) 
      {
        cxi.logoff();
        cxi.close();
      }
    }
    
    System.out.println("Done");
  }    

}
