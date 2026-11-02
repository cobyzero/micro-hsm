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
 * Authentication methods
 *
 * @note In favour of better understandability exception handling has been removed to a minimum.
 */
public class demoAuthentication
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
    
      // logon user with HMAC hashed password
      cxi.logon("CXI_HMAC", "", "12345678".getBytes());
      
      // logon user with key file
      cxi.logon("ADMIN", "init_dev_prv.key", null);
      
      // logon user with password encrypted key file
      cxi.logon("ADMIN", "init_dev_prv_enc.key", "12345678".getBytes());
      
      // logon user with smartcard / reader connected to USB
      System.out.println("please mind the PIN pad");
      cxi.logon("ADMIN", ":cs2:cyb:USB0", null);
      
      // show resulting authentication state
      int auth_state = cxi.getAuthState();
      System.out.println("AuthState: " + String.format("%08x", auth_state));
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
