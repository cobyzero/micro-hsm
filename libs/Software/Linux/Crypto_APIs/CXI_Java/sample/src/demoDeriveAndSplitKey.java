import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import CryptoServerAPI.CryptoServerUtil;
import CryptoServerCXI.CryptoServerCXI;

/**
 * This program illustrates the usage of the CryptoServerCXI to call DeriveKey and SplitKey.
 *
 */
public class demoDeriveAndSplitKey
{
  
	protected static final byte [] TAG_CF  = { (byte)'C', (byte)'F' };
	protected static final byte [] TAG_MP  = { (byte)'M', (byte)'P' };
	protected static final byte [] TAG_PL  = { (byte)'P', (byte)'L' };
	
	private static final int CXI_MDL_ID = 0x068;
	private static final int CXI_KEY_TYPE_SECRET = 0x00000008;
	private static final int CXI_MECH_HASH_ALGO_SHA256 = 0x00000040;
	private static final int CXI_MECH_KDF_TLS12_PRF = 0xD0000000;
	private static final int CXI_KEY_USAGE_DERIVE = 0x00000004;
	
	private static final int SFC_DERIVE_KEY = 28;
	private static final int SFC_SPLIT_KEY = 43;
	
	private static final String group = "test1";
	 
	 
  public static void main(String[] args) throws Exception 
  {    
    String device = System.getenv("CRYPTOSERVER");        
    if (device == null) device = "3001@127.0.0.1";
    
    CryptoServerCXI cxi = null;
    
    try
    {  
      cxi = new CryptoServerCXI(device, 3000);
      cxi.setTimeout(60000);
      cxi.logon("MYADMIN", "", "12345678".getBytes());
      System.out.println("Connected and logged on the CXI server\n");
	  
	  ////////////////////////////////////////////////////
	  // Calling Derive Key with CXI_MECH_KDF_TLS12_PRF //
	  ////////////////////////////////////////////////////
	  
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      byte[] buff4 = new byte[4];
      byte[] buff2 = new byte[2];
      
      // Command flags
      os.write(TAG_CF);
      CryptoServerUtil.store_int4(4, buff4, 0);
      os.write(buff4);
      CryptoServerUtil.store_int4(CryptoServerCXI.FLAG_OVERWRITE, buff4, 0);
      os.write(buff4);
      
      // Create demo AES key
      CryptoServerCXI.Key Key = generateAESkey(cxi);
      os.write(Key.getEncoded()); // this already contains the K and KH tags!
           
      // Mechanism parameter
      os.write(TAG_MP);
      CryptoServerUtil.store_int4(89, buff4, 0); // 4+2+2+13+2+32+2+32 = 89 = size of the MP block
      os.write(buff4);
      CryptoServerUtil.store_int4(CXI_MECH_KDF_TLS12_PRF | CXI_MECH_HASH_ALGO_SHA256, buff4, 0);
      os.write(buff4);
      CryptoServerUtil.store_int2(0, buff2, 0); // l_prefix
      os.write(buff2);
      CryptoServerUtil.store_int2(13, buff2, 0); // l_label
      os.write(buff2);
      os.write("master secret".getBytes()); // label (13 characters)
      
      CryptoServerUtil.store_int2(32, buff2, 0); // l_seed1
      os.write(buff2);
      byte[] seed1 = new byte[32];
      SecureRandom.getInstanceStrong().nextBytes(seed1); // random seed1
      os.write(seed1);
      
      CryptoServerUtil.store_int2(32, buff2, 0); // l_seed2
      os.write(buff2);
      byte[] seed2 = new byte[32];
      SecureRandom.getInstanceStrong().nextBytes(seed2); // random seed2
      os.write(seed2);
           
      // Key template
      os.write(TAG_PL);
      CryptoServerUtil.store_int4(24, buff4, 0); // 2+2+4+2+2+4+2+2+4 = 24 = size of the PL block
      os.write(buff4);
      
      CryptoServerUtil.store_int2(CryptoServerCXI.KeyAttributes.PROP_KEY_ALGO, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int2(4, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int4(CryptoServerCXI.KEY_ALGO_AES, buff4, 0);
      os.write(buff4);
 
      CryptoServerUtil.store_int2(CryptoServerCXI.KeyAttributes.PROP_KEY_SIZE, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int2(4, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int4(128, buff4, 0); // AES 128 bits
      os.write(buff4);
      
      CryptoServerUtil.store_int2(CryptoServerCXI.KeyAttributes.PROP_KEY_TYPE, buff2, 0);
      os.write(buff2);  
      CryptoServerUtil.store_int2(4, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int4(CXI_KEY_TYPE_SECRET, buff4, 0);
      os.write(buff4);
    
      System.out.println("--- Calling Derive Key with two random seeds ---");
      byte [] answ1 = cxi.exec(CXI_MDL_ID, SFC_DERIVE_KEY, os.toByteArray());
      System.out.println("SUCCESS! The result is a key handle: "+new String(answ1)+"\n");
      
      ///////////////////////
      // Calling Split Key //
      ///////////////////////
     
      // Create demo RAW key
      os.reset();
      CryptoServerCXI.Key RawKey = generateRAWkey(cxi);
      os.write(RawKey.getEncoded()); // this already contains the K and KH tags!
      
      // Key Flags 1
      os.write(TAG_CF);
      CryptoServerUtil.store_int4(8, buff4, 0);
      os.write(buff4);
      CryptoServerUtil.store_int4(CryptoServerCXI.FLAG_VOLATILE, buff4, 0);
      os.write(buff4);
      CryptoServerUtil.store_int4(0, buff4, 0); // offset
      os.write(buff4);
      
      // Key template 1
      os.write(TAG_PL);
      CryptoServerUtil.store_int4(24, buff4, 0); // 2+2+4+2+2+4+2+2+4 = 24 = size of the PL block
      os.write(buff4);
      
      CryptoServerUtil.store_int2(CryptoServerCXI.KeyAttributes.PROP_KEY_ALGO, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int2(4, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int4(CryptoServerCXI.KEY_ALGO_AES, buff4, 0);
      os.write(buff4);
 
      CryptoServerUtil.store_int2(CryptoServerCXI.KeyAttributes.PROP_KEY_SIZE, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int2(4, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int4(128, buff4, 0); // AES 128 bits
      os.write(buff4);
      
      CryptoServerUtil.store_int2(CryptoServerCXI.KeyAttributes.PROP_KEY_TYPE, buff2, 0);
      os.write(buff2);  
      CryptoServerUtil.store_int2(4, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int4(CXI_KEY_TYPE_SECRET, buff4, 0);
      os.write(buff4);
      
      // Key Flags 2
      os.write(TAG_CF);
      CryptoServerUtil.store_int4(8, buff4, 0);
      os.write(buff4);
      CryptoServerUtil.store_int4(0, buff4, 0);
      os.write(buff4);
      CryptoServerUtil.store_int4(0, buff4, 0); // offset
      os.write(buff4);
      
      // Key template 2
      os.write(TAG_PL);
      CryptoServerUtil.store_int4(24, buff4, 0); // 2+2+4+2+2+4+2+2+4 = 24 = size of the PL block
      os.write(buff4);
      
      CryptoServerUtil.store_int2(CryptoServerCXI.KeyAttributes.PROP_KEY_ALGO, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int2(4, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int4(CryptoServerCXI.KEY_ALGO_AES, buff4, 0);
      os.write(buff4);
 
      CryptoServerUtil.store_int2(CryptoServerCXI.KeyAttributes.PROP_KEY_SIZE, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int2(4, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int4(128, buff4, 0); // AES 128 bits
      os.write(buff4);
      
      CryptoServerUtil.store_int2(CryptoServerCXI.KeyAttributes.PROP_KEY_TYPE, buff2, 0);
      os.write(buff2);  
      CryptoServerUtil.store_int2(4, buff2, 0);
      os.write(buff2);
      CryptoServerUtil.store_int4(CXI_KEY_TYPE_SECRET, buff4, 0);
      os.write(buff4);
      
      System.out.println("--- Calling Split Key ---");
      byte [] answ2 = cxi.exec(CXI_MDL_ID, SFC_SPLIT_KEY, os.toByteArray());
      System.out.println("SUCCESS! The result is a list of key handles: "+new String(answ2)+"\n");
    }
    finally
    {      
      System.out.println("Closing connection");            
      if (cxi != null) 
      {
        cxi.logoff();
        cxi.close();
      }
    }
  }  
 
  // generate an AES Key
  private static CryptoServerCXI.Key generateAESkey(CryptoServerCXI cxi) throws Exception {
	  CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_AES);
      attr.setSize(256);
      attr.setName("AES_DEMO_KEY");
      attr.setGroup(group);
      attr.setUsage(CXI_KEY_USAGE_DERIVE);
      return cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr);
  }
  
 //generate a RAW Key
 private static CryptoServerCXI.Key generateRAWkey(CryptoServerCXI cxi) throws Exception {
	 CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
     attr.setAlgo(CryptoServerCXI.KEY_ALGO_RAW);
     attr.setSize(1024);
     attr.setName("RAW_DEMO_KEY");
     attr.setGroup(group);
     attr.setUsage(CXI_KEY_USAGE_DERIVE);
     return cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr);
 }
}
