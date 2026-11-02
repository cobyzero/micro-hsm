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
 * AES
 *
 * @note In favour of better understandability exception handling has been removed to a minimum.
 */
public class demoAES
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
      
      // generate key
      System.out.println("generate AES key...");
      CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_AES);
      attr.setSize(256);      
      attr.setName("AES_DEMO_KEY");
      attr.setGroup(group);
      
      CryptoServerCXI.Key aesKey = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr);
      
      // encrypt data in CBC mode (demostrates chunked encryption)  
      String text = "Oh, say can you see by the dawn's early light\n" 
                  + "What so proudly we hailed at the twilights last gleaming?\n"
                  + "Whose broad stripes and broght stars thru the perilous fight,\n"
                  + "O'er the ramparts we watched were so gallantly streaming?\n"
                  + "And the rocket's red glare, the bombs bursting in air,\n"
                  + "Gave proof through the night that our flag was still there.\n"
                  + "Oh, say does that star-spangled banner yet wave\n"
                  + "O'er the land of the free and the home of the brave?\n";
      
      System.out.println("encrypt data...");      
      byte [] data = text.getBytes();      
      byte [] crypto = new byte[0];
      CryptoServerCXI.ByteArray iv = new CryptoServerCXI.ByteArray();
      
      int mech = CryptoServerCXI.MECH_MODE_ENCRYPT | CryptoServerCXI.MECH_CHAIN_CBC;                 
      int rlen = data.length;
      int ofs = 0;
      int len = 16;
      
      while (rlen > 0)
      {        
        if (rlen <= 16)
        {
          len = rlen;
          // apply padding on last block
          mech |= CryptoServerCXI.MECH_PAD_PKCS5;  
        }
        
        byte [] chunk = copyOf(data, ofs, len);
        
        crypto = concat(crypto, cxi.crypt(0, aesKey, mech, null, chunk, iv, null, null));
        
        rlen -= len;
        ofs += len;
      }
      
      CryptoServerUtil.xtrace("data", data);
      CryptoServerUtil.xtrace("encrypted data", crypto);
      
      // AES decrypt data (in one shot)
      System.out.println("decrypt data...");
      mech = CryptoServerCXI.MECH_MODE_DECRYPT | CryptoServerCXI.MECH_CHAIN_CBC | CryptoServerCXI.MECH_PAD_PKCS5;
      byte [] plain = cxi.crypt(aesKey, mech, null, crypto, null);
      //CryptoServerUtil.xtrace("decrypted data", plain);
      System.out.println(new String(plain));
      
      if (!Arrays.equals(plain, data))
        throw new CryptoServerException(-1, "decrypted data doesn't match original data");
        
      // delete all keys
      System.out.println("delete all demo keys...");
      
      CryptoServerCXI.KeyAttributes keyTemplate = new CryptoServerCXI.KeyAttributes();
      keyTemplate.setGroup(group);
      CryptoServerCXI.KeyAttributes [] keyList = cxi.listKeys(keyTemplate);
      
      for (CryptoServerCXI.KeyAttributes keyattr : keyList)
      {
        CryptoServerCXI.Key key = cxi.findKey(keyattr);
        cxi.deleteKey(key);
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
