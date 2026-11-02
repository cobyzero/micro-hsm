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
 * External key store
 *
 * @note In favour of better understandability exception handling has been removed to a minimum.
 */
public class demoKeyStore
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
    
      // logon
      cxi.logon("CXI_HMAC", "", "12345678".getBytes());
      
      // open / create external key store
      CryptoServerCXI.KeyStore ks = new CryptoServerCXI.KeyStore("./cxi.ks", 16);
      
      // generate an AES key (external key storage)
      System.out.println("generating AES key...");
      CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_AES);
      attr.setSize(256);
      attr.setName("AES test key");      
      attr.setGroup(group);
      
      CryptoServerCXI.Key aesKey = cxi.generateKey(CryptoServerCXI.FLAG_EXTERNAL, attr);      
      
      // store key in external key store (use first free index);
      byte [] index = ks.insertKey(CryptoServerCXI.FLAG_OVERWRITE, null, aesKey);
            
      //index = "\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x6\x6\x6".getBytes();
      index = new byte [] { 0,0,0,0,0,0,0,0,0,0,0,0,0,6,6,6 };
      CryptoServerUtil.xtrace(index);
      ks.insertKey(CryptoServerCXI.FLAG_OVERWRITE, index, aesKey);
      
      // store key again but use original key index 
      index = aesKey.getUName();
      ks.insertKey(CryptoServerCXI.FLAG_OVERWRITE, index, aesKey); 
      
      // generate an RSA key (external key storage)
      System.out.println("generating RSA key...");
      attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_RSA);
      attr.setSize(1024);
      attr.setName("RSA test key");
      attr.setGroup(group);      
      CryptoServerCXI.Key rsaKey = cxi.generateKey(CryptoServerCXI.FLAG_EXTERNAL, attr);
      
      // store key in external key store   
      index = rsaKey.getUName();
      ks.insertKey(CryptoServerCXI.FLAG_OVERWRITE, index, rsaKey);            
      
      // find only RSA keys       
      index = new byte[ks.getIndexLength()];
      int mode = CryptoServerCXI.KeyStore.MODE_GTEQ;
      
      attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_RSA);
      
      while (ks.findKey(index, mode, attr) == true)
      {        
        CryptoServerCXI.Key key = ks.getKey(index);
        
        // sign data with key
        byte [] hash = cxi.generateRandom(20, CryptoServerCXI.MECH_RND_PSEUDO);
        int mech = CryptoServerCXI.MECH_PAD_PKCS1 | CryptoServerCXI.MECH_HASH_ALGO_SHA1;
        byte [] sign = cxi.sign(key, mech, hash);
        
        mode = CryptoServerCXI.KeyStore.MODE_GREATER;
      }
      
      // list all keys
      System.out.println("listing all keys...");
      index = new byte[ks.getIndexLength()];
      mode = CryptoServerCXI.KeyStore.MODE_GTEQ;
      
      System.out.printf("%-33s %-16s %s\n", "index", "group", "name");
      System.out.println("--------------------------------------------------------------------------------");
        
      while (ks.findKey(index, mode, null) == true)
      {
        //CryptoServerUtil.xtrace("index", index);        
        CryptoServerCXI.Key key = ks.getKey(index); 
        attr = key.getAttributes();

        System.out.printf("%-33s %-16s %s\n", toHexString(index),
                                              attr.getGroup(),
                                              attr.getName());
                                               
        mode = CryptoServerCXI.KeyStore.MODE_GREATER;
        ks.deleteKey(index);
      }
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
  
  static String toHexString(byte [] a)
  {
    int ofs = 0;
    int len = a.length;
    final byte [] hexchars = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    
    byte [] buf = new byte[2*len];
    int idx = 0;
    
    while (len-- > 0)
    {
      int c = (int)a[ofs] & 0xFF;            
      buf[idx++] = hexchars[c >> 4];
      buf[idx++] = hexchars[c & 0xF];
      ofs++;
    }
    
    return new String(buf);
  }    
}
