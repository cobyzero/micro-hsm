import CryptoServerAPI.*;
import CryptoServerCXI.*;

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.math.*;

/**
 * This program illustrates the usage of the CryptoServerCXI API for the CryptoServer Hardware Security Module.
 *
 * Hash Calculation
 *
 * @note In favour of better understandability exception handling has been removed to a minimum.
 */
public class demoHash
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
    
    try
    {    
      // create instance of CryptoServerCXI (opens connection to CryptoServer)
      cxi = new CryptoServerCXI(device, 3000);
      cxi.setTimeout(60000);
      
      System.out.println("device: " + cxi.getDevice());
      
      // logon
      cxi.logon("CXI_HMAC", "", "12345678".getBytes());
      
      // generate random data to be hashed
      int data_len = (int)(Math.random() * 1000);
      byte [] data = cxi.generateRandom(data_len, -1);
      System.out.println("data length: " + data.length);
      
      // chunked hash calculation            
      int flags = CryptoServerCXI.FLAG_HASH_PART;
      int mech = CryptoServerCXI.MECH_MODE_HASH | CryptoServerCXI.MECH_HASH_ALGO_SHA256;           
      int len = 64;      
      int ofs = 0;
      byte [] hash = null;
      
      while (data_len > 0)
      {
        if (data_len <= 64)
        {
          flags = 0;
          len = data_len;
        }
        
        byte [] chunk = copyOf(data, ofs, len);
        hash = cxi.computeHash(flags, mech, chunk, hash, null);
        
        data_len -= len;
        ofs += len;
      }
      
      CryptoServerUtil.xtrace("hash", hash);
      
      // recalculate in one shot
      byte [] rhash = cxi.computeHash(0, mech, data, null, null);      
      CryptoServerUtil.xtrace("recalculated hash (one shot)", rhash);
      
      if (!Arrays.equals(hash, rhash))
        throw new CryptoServerException(-1, "hash doesn't match reference hash");
      
      // recalculate locally
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(data);
      rhash = md.digest();
      
      CryptoServerUtil.xtrace("recalculated hash (local)", rhash);
      
      if (!Arrays.equals(hash, rhash))
        throw new CryptoServerException(-1, "hash doesn't match reference hash");
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
