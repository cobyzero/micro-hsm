import CryptoServerAPI.*;
import CryptoServerCXI.*;

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;

/**
 * This program illustrates the usage of the CryptoServerCXI API for the CryptoServer Hardware Security Module.
 *
 * CryptoServer Cluster
 *
 * @note In favour of better understandability exception handling has been removed to a minimum.
 */
public class demoCluster
{  
  static class EventHandler implements CryptoServerCluster.EventHandler
  {
    public void stateChanged(String device, int state)
    {
      System.out.println("I: state of " + device + " changed to: " + CryptoServerCluster.DeviceState.valueOf(state));
    }
    
    public void errorOccurred(String device, int err, String where, String message)
    {
      System.out.println( "E: error occurred on " + device + " at " + where 
                        + "\ncode: 0x" + Integer.toHexString(err) 
                        + "\nmessage: " + message);
    }
  }
  
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer CXI Demo ---\n");    
    
    // load configuration
    CryptoServerConfig config = new CryptoServerConfig("./cxi.cfg");
    config.dump();
    
    // enable logging
    CryptoServerCXI.CxiLog.init(config);
    
    CryptoServerCXI cxi = null;
    
    try
    {       
      // connect to CryptoServer cluster      
      cxi = new CryptoServerCXI(config);

      System.out.println("current device: " + cxi.getDevice());      
            
      // String [] devices = new String [] { "3001@127.0.0.1", "PCI:0", "192.168.4.183" };
      // cxi = new CryptoServerCXI(devices, 3000);
                        
      // optionally set individual event handler (otherwise events are written to log file)
      cxi.setEventHandler(new EventHandler());

      // logon to cluster
      cxi.logon("CXI_HMAC", "", "12345678".getBytes());

      // generate RSA key
      System.out.println("generating RSA key ...");
      CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_RSA);
      attr.setSize(2048);                
      attr.setName("RSA_DEMO_KEY");
      attr.setGroup("test");
      CryptoServerCXI.Key rsaKey = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr);
      
      // ...
      
      // open previously generated RSA key
      attr = new CryptoServerCXI.KeyAttributes();
      attr.setName("RSA_DEMO_KEY");
      attr.setGroup("test");
      
      rsaKey = cxi.findKey(attr);
      
      // hash data
      System.out.println("hash data...");      
      MessageDigest md = MessageDigest.getInstance("SHA-512", "SUN");
      byte [] data = "Yes we can".getBytes();
      md.update(data, 0, data.length);
      byte [] hash = md.digest();
      
      // RSA sign hash       
      System.out.println("RSA sign data...");      
      int mech = CryptoServerCXI.MECH_HASH_ALGO_SHA512 | CryptoServerCXI.MECH_PAD_PKCS1;
      byte [] sign = null;
      
      System.out.println("  try to disconnect curent device while test is running and see how the API switches to another device");
      System.out.println("  press <enter> to interrupt loop");
      
      for (int i=999; --i>=0; )
      {               
        System.out.printf("\rcount: %3d", i);
        sign = cxi.sign(rsaKey, mech, hash);
        
        // try to disconnect current device here and see how the API switches to another device        
        if (System.in.available() != 0) break;
        Thread.sleep(100);
      }
      CryptoServerUtil.xtrace("\nsignature", sign);
      
      // RSA verify signature
      System.out.println("RSA verify signature...");
      boolean result = cxi.verify(rsaKey, mech, hash, sign);
      System.out.println("Signature verification: " + result);
    }
    finally
    {
      System.out.println("closing connection...");
      
      if (cxi != null) 
      {
        cxi.logoff();
        cxi.close();
      }
    }
    
    System.out.println("Done");
  }    
}
