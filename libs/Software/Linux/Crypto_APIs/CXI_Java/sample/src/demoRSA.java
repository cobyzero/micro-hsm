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
 * RSA
 *
 * @note In favour of better understandability exception handling has been removed to a minimum.
 */
public class demoRSA
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
      
      // generate RSA key
      System.out.println("generate RSA key...");
      CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_RSA);
      attr.setSize(2048);
      attr.setName("RSA_DEMO_KEY");
      attr.setGroup(group);
      
      CryptoServerCXI.Key rsaKey = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr);
      
      // export public RSA key part
      System.out.println("export public part of RSA key...");
      CryptoServerCXI.KeyAttAndComp kb = cxi.exportClearKey(rsaKey, CryptoServerCXI.KEY_TYPE_PUBLIC);
      byte [] modulus = kb.keyComponents.getItem(CryptoServerCXI.KeyComponents.TYPE_MOD);
      CryptoServerUtil.xtrace("modulus", modulus);      
      byte [] pexp = kb.keyComponents.getItem(CryptoServerCXI.KeyComponents.TYPE_PEXP);                              
      CryptoServerUtil.xtrace("public exponent", pexp);
      
      // encrypt data
      System.out.println("encrypting data...");
      int mech = CryptoServerCXI.MECH_MODE_ENCRYPT | CryptoServerCXI.MECH_PAD_PKCS1;
      byte [] data = "Yes we can!".getBytes();
      byte [] crypto = cxi.crypt(rsaKey, mech, null, data, null);
      
      // decrypt data
      System.out.println("decrypting data...");
      mech = CryptoServerCXI.MECH_MODE_DECRYPT | CryptoServerCXI.MECH_PAD_PKCS1;
      byte [] plain = cxi.crypt(rsaKey, mech, null, crypto, null);
      
      if (!Arrays.equals(plain, data)) 
        throw new CryptoServerException(-1, "decrypted data doesn't match originla data");
      
      // hash data
      System.out.println("hash data...");
      MessageDigest md = MessageDigest.getInstance("SHA-512", "SUN");
      md.update(data, 0, data.length);
      byte [] hash = md.digest();
      
      // RSA sign hash       
      System.out.println("sign data...");      
      mech = CryptoServerCXI.MECH_HASH_ALGO_SHA512 | CryptoServerCXI.MECH_PAD_PKCS1;
      byte [] sign = cxi.sign(rsaKey, mech, hash);
      CryptoServerUtil.xtrace("signature", sign);
      
      // RSA verify signature      
      System.out.println("verify signature...");
      boolean result = cxi.verify(rsaKey, mech, hash, sign);
      
      if (result != true)
        throw new CryptoServerException(-1, "signature verification failed");
            
      // mainpulate signature      
      System.out.println("verify manipulated signature...");
      sign[5] += 1;
      result = cxi.verify(rsaKey, mech, hash, sign);
      
      if (result == true)
        throw new CryptoServerException(-1, "verification of manipulated signature succeded (?)");
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
  
  // concat
  static private byte [] concat(byte [] a, byte [] b)
  {
    byte [] res = new byte[a.length + b.length];
    
    System.arraycopy(a, 0, res, 0, a.length);
    System.arraycopy(b, 0, res, a.length, b.length);
    
    return res;
  }
  
  // copyOf
  static byte [] copyOf(byte [] a, int ofs, int len)
  {
    byte [] res = new byte[len];
    
    System.arraycopy(a, ofs, res, 0, len);
    return res;
  }  
}
