import CryptoServerCXI.*;
import CryptoServerAPI.*;
import java.util.Arrays;


/**
 * This program illustrates the usage of the CryptoServerCXI API for the CryptoServer Hardware Security Module.
 *
 * AES GCM
 * 	Creates a random data block to be encrypted. Allocates variables for block length for experimentation
 *  Allows associated data to be included.
 *  Provides code for both GCM and GMAC
 *  
 *
 * @note In favour of better understandability exception handling has been removed to a minimum.
 */
public class demoAESGCM
{

  static CryptoServerCXI cxi = null;
  static String group = "test1";    
	  
  static private int random(int min, int max) throws Exception
  {
	    byte [] data = cxi.generateRandom(2,0);    
	    int len = CryptoServerUtil.load_int2(data, 0);
	    
	    return (len % (max - min)) + min;
  }
  
  public static void main(String[] args) throws Exception 
  {
    System.out.println("\n--- Utimaco CryptoServer CXI Demo - AESGCM ---\n");    
        
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
	  
	    System.out.format("device: " + cxi.getDevice());
	
	    // logon
	    cxi.logon("CXI_HMAC", "", "12345678".getBytes());
	
	    System.out.format("\n");

		int size = 256;  
	    // generate key
		System.out.format("key size: %d\n", size);
	    
	    CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
	    attr.setAlgo(CryptoServerCXI.KEY_ALGO_AES);
	    attr.setSize(size);     
	    attr.setName("CXI_AES_KEY");
	    attr.setGroup(group);
	    
	    CryptoServerCXI.Key key = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr, 0);
	    
	    // encrypt data in GCM mode (demostrates chunked encryption)  
	    // generate random data with random length
	    int dataLength = random(500, 1000);          
	    byte [] data = cxi.generateRandom(dataLength, 0);
	
	    // Let's chunk the data at block length of 16
	    int chunkLength = 16;
	    
	    System.out.format("  data length : %d\n", dataLength);        
	    
	    // For this example, set associated_data to a secret string.
	    byte [] associated_data = "My Little Secret".getBytes();
	    byte [] ivInit = cxi.generateRandom(12, 0);
	    CryptoServerCXI.ByteArray iv = new CryptoServerCXI.ByteArray();
        int tagLength = 128;
	    CryptoServerCXI.ByteArray tag0 = new CryptoServerCXI.ByteArray();        
	                       
	    // 1. encrypt data                           
	    int mech = CryptoServerCXI.MECH_MODE_ENCRYPT | CryptoServerCXI.MECH_CHAIN_GCM;
	    CryptoServerCXI.MechParamGCM mechParamGCM;    
	            
	    // Allocate Encrypted Result Buffer
	    byte [] crypto = new byte[0];
	    
	    System.out.format("  encrypt: chunk length: %d\n", chunkLength);        
	    
	    for (int ofs=0; dataLength>0; ofs += chunkLength)
	    {                   
	      if (chunkLength > dataLength) chunkLength = dataLength;
	      
	      dataLength -= chunkLength;
	      
	      if (ofs == 0)
	      {
	        // first block (may also be final block)
	        mechParamGCM = new CryptoServerCXI.MechParamGCM(ivInit, associated_data, tagLength);
	      }
	      else if (dataLength == 0)
	      {
	        // final block
	        mechParamGCM = new CryptoServerCXI.MechParamGCM(ivInit, null, tagLength);
	      }
	      else
	      {
	        // intermediate block
	        mechParamGCM = new CryptoServerCXI.MechParamGCM(null, null, tagLength);
	      }
	      
	      int flags = (dataLength == 0) ? CryptoServerCXI.FLAG_CRYPT_FINAL : 0;
	      
	      byte [] chunk = CryptoServerUtil.copyOf(data, ofs, chunkLength);                           
	      byte [] res = cxi.crypt(flags, key, mech, mechParamGCM.getEncoded(), chunk, iv, tag0, null);
	      
	      crypto = CryptoServerUtil.concat(crypto, res);
	    }
	    
	    // 2. decrypt data
	    dataLength = crypto.length;
	    chunkLength = 64;
	    
	    iv.clear();
	    CryptoServerCXI.ByteArray tag1 = new CryptoServerCXI.ByteArray();
	    mech = CryptoServerCXI.MECH_MODE_DECRYPT | CryptoServerCXI.MECH_CHAIN_GCM;
	    byte [] plain = new byte [0];
	    
	    System.out.format("  decrypt: chunk length: %d\n", chunkLength);
	    
	    for (int ofs=0; dataLength>0; ofs += chunkLength)
	    {          
	      if (chunkLength > dataLength) chunkLength = dataLength;
	      
	      dataLength -= chunkLength;
	      
	      if (ofs == 0)
	      {
	        // first block (may also be final block)
	        mechParamGCM = new CryptoServerCXI.MechParamGCM(ivInit, associated_data, tagLength);
	      }
	      else if (dataLength == 0)
	      {
	        // final block
	        mechParamGCM = new CryptoServerCXI.MechParamGCM(ivInit, null, tagLength);
	      }
	      else
	      {
	        // intermediate block
	        mechParamGCM = new CryptoServerCXI.MechParamGCM(null, null, tagLength);
	      }
	      
	      int flags = (dataLength == 0) ? CryptoServerCXI.FLAG_CRYPT_FINAL : 0;
	      
	      byte [] chunk = CryptoServerUtil.copyOf(crypto, ofs, chunkLength);                           
	      byte [] res = cxi.crypt(flags, key, mech, mechParamGCM.getEncoded(), chunk, iv, tag1, tag0.getBytes());
	      
	      plain = CryptoServerUtil.concat(plain, res);
	    }
	    
	    if (  plain.length != data.length || !Arrays.equals(plain,data))
	      throw new Exception("data comparison failed\n");
	    
	    // 3. create MAC
	    dataLength = data.length;
	    chunkLength = 64;
	            
	    iv.clear();
	    byte [] mac = null;
	    int flags = 0;
	    
	    mech = CryptoServerCXI.MECH_CHAIN_GCM;
	    CryptoServerCXI.MechParamGMAC mechParamGMAC = new CryptoServerCXI.MechParamGMAC(null);
	    
	    System.out.format("  sign: chunk length: %d\n", chunkLength);
	
	    for (int ofs=0; dataLength>0; ofs += chunkLength)
	    {
	      if (chunkLength > dataLength) chunkLength = dataLength;
	
	      dataLength -= chunkLength;
	      
	      if (dataLength == 0)
	      {
	        mechParamGMAC = new CryptoServerCXI.MechParamGMAC(ivInit);
	        flags = CryptoServerCXI.FLAG_CRYPT_FINAL;
	      }
	      
	      byte [] chunk = CryptoServerUtil.copyOf(data, ofs, chunkLength);   
	      
	      mac = cxi.sign(flags, key, mech, mechParamGMAC.getEncoded(), chunk, iv);
	    }   
	    
	    // 4. recalculate MAC
        byte [] mac2 = null;
	    mechParamGMAC = new CryptoServerCXI.MechParamGMAC(ivInit);
	    mac2 = cxi.sign(CryptoServerCXI.FLAG_CRYPT_FINAL, key, mech, mechParamGMAC.getEncoded(), data, null);
	    
	    if (  mac.length != mac2.length || !Arrays.equals(mac, mac2))
	      throw new Exception("MAC recalculation failed\n");      
	      
	    // 5. verify MAC
	    System.out.format("  verify\n");
	    
	    boolean result = cxi.verify(CryptoServerCXI.FLAG_CRYPT_FINAL, key, mech, mechParamGMAC.getEncoded(), data, mac, null);
	    
	    if (result == false)
	      throw new Exception("MAC verification failed\n");
    }
    finally
    {
      System.out.format("closing connection\n");          
      if (cxi != null) 
      {
        cxi.logoff();
        cxi.close();
      }
    }
      
    System.out.format("Done\n");
  }
}

