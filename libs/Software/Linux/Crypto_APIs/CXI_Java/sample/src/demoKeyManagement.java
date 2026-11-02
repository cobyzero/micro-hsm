import CryptoServerAPI.*;
import CryptoServerCXI.*;

import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;
import java.text.*;
import java.math.BigInteger;

/**
 * This program illustrates the usage of the CryptoServerCXI API for the CryptoServer Hardware Security Module.
 *
 * Key Management
 *
 * @note In favour of better understandability exception handling has been removed to a minimum.
 */
public class demoKeyManagement
{
  static final String algoStrings [] = new String [] { "RAW", "DES", "AES", "RSA", "ECDSA", "DSA", "ECDH", "DH" };  
  static final String exportStrings [] = new String [] { "???", "allowed", "allowed(plain)", "allowed(plain)" }; 
  
  static private final String getTypeString(int type)
  {
    switch (type)    
    {
      case CryptoServerCXI.KEY_TYPE_PUBLIC: return "public";
      case CryptoServerCXI.KEY_TYPE_SECRET: return "secret";
      case CryptoServerCXI.KEY_TYPE_PRIVATE_ONLY: return "prv";
      case CryptoServerCXI.KEY_TYPE_PRIVATE: return "prv+pub";
      case CryptoServerCXI.KEY_TYPE_PRIVATEF: return "prv-full";      
      case CryptoServerCXI.KEY_TYPE_DATA: return "data";
      case CryptoServerCXI.KEY_TYPE_CERT: return "cert";
      case CryptoServerCXI.KEY_TYPE_DOMAIN_PARAMETER: return "dp";      
      case CryptoServerCXI.KEY_TYPE_CONFIG: return "conf";
      default:
        return ("TYPE_" + type);
    }
  }
  
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
    
      //--------------------------------------------------------------------------------
      // logon
      //--------------------------------------------------------------------------------
      cxi.logon("CXI_HMAC", "", "12345678".getBytes());
      
      // optionally logon a second user
      // cxi.logon("bill", "rsa.key", null);
      
      //--------------------------------------------------------------------------------
      // generate AES key
      //--------------------------------------------------------------------------------
      CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_AES);
      attr.setSize(256);
      attr.setGroup(group);
      attr.setName("CXI_AES_GEN_KEY");
      
      CryptoServerCXI.Key aesKey = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr);
      
      // generate RSA key
      attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_RSA);
      attr.setSize(2048);
      attr.setGroup(group);
      attr.setName("CXI_RSA_GEN_KEY");
      attr.setExport(CryptoServerCXI.KEY_EXPORT_ALLOW);        
      attr.setGenerationDate(new Date());      
      attr.setExpirationDate(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").parse("2012-12-21 11:55:00"));
      
      CryptoServerCXI.Key rsaKey = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr); 
      
      //--------------------------------------------------------------------------------
      // retrieve key attributes of RSA key
      //--------------------------------------------------------------------------------      
      attr = cxi.getKeyAttributes(rsaKey, true);
      System.out.println("Key Attributes:");
      System.out.println("  algo      : " + algoStrings[attr.getAlgo()]);
      System.out.println("  type      : " + getTypeString(attr.getType()));
      System.out.println("  size      : " + attr.getSize());
      System.out.println("  group     : " + attr.getGroup());
      System.out.println("  name      : " + attr.getName());
      System.out.println("  specifier : " + attr.getSpecifier());
      System.out.println("  export    : " + Integer.toString(attr.getExport(), 16));
      System.out.println("  usage     : " + Integer.toString(attr.getUsage(), 16));
      System.out.println("  date gen. : " + attr.getGenerationDate());
      System.out.println("  date exp. : " + attr.getExpirationDate());      
      System.out.println("  label     : " + attr.getLabel());
      System.out.println("  modulus   : ");
      CryptoServerUtil.xtrace(attr.getModulus());
      System.out.println("  exponent  : ");
      CryptoServerUtil.xtrace(attr.getExponent());
      
      //--------------------------------------------------------------------------------
      // generate ECDSA key
      //--------------------------------------------------------------------------------      
      attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_ECDSA);
      attr.setCurve("NIST-P256");
      attr.setGroup(group);
      attr.setName("CXI_EC_GEN_KEY");
      attr.setExport(CryptoServerCXI.KEY_EXPORT_ALLOW_PLAIN);  // don't do this!
      
      CryptoServerCXI.Key ecKey = cxi.generateKey(CryptoServerCXI.FLAG_OVERWRITE, attr);
            
      //--------------------------------------------------------------------------------
      // import clear text AES key
      //--------------------------------------------------------------------------------
      attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_AES);
      attr.setSize(256);
      attr.setGroup(group);
      attr.setName("CXI_AES_IMP_KEY");
      
      final byte [] aesKeyBytes = {(byte)0xB7, (byte)0xF3, (byte)0x89, (byte)0x3A, (byte)0xAB, (byte)0x15, (byte)0x0B, (byte)0xAF, 
                                   (byte)0xEC, (byte)0xC1, (byte)0x93, (byte)0x10, (byte)0x97, (byte)0x89, (byte)0x3C, (byte)0x38, 
                                   (byte)0x75, (byte)0x1A, (byte)0xD7, (byte)0x28, (byte)0xDD, (byte)0x56, (byte)0xDE, (byte)0xB8,
                                   (byte)0xF1, (byte)0xA4, (byte)0x10, (byte)0x97, (byte)0x75, (byte)0x5B, (byte)0x5E, (byte)0x06 };
      
      CryptoServerCXI.KeyComponents comp = new CryptoServerCXI.KeyComponents(aesKeyBytes);
      
      aesKey = cxi.importClearKey(CryptoServerCXI.FLAG_OVERWRITE, CryptoServerCXI.KEY_BLOB_SIMPLE, attr, comp);
      
      //--------------------------------------------------------------------------------
      // import clear text RSA key
      //--------------------------------------------------------------------------------
      attr = new CryptoServerCXI.KeyAttributes();
      attr.setAlgo(CryptoServerCXI.KEY_ALGO_RSA);
      attr.setSize(1024);
      attr.setGroup(group);
      attr.setName("CXI_RSA_IMP_KEY");      
      
      final String mod  = "B7F3893AAB150BAFECC1931097893C38751AD728DD56DEB8F1A41097755B5E0664FF32FD902B04EDCFD5E2EF8330FDF07C15F9C2229E53F71446EEDBC82BEA3D1679B2BBC07B269D0832D098B3478189CB1FD9F770ED5231EE9AA05BEBE2D0F13F4813F919EB8B3B14AEEE0EE22EDEB152CB5B5798712CDE28273B7E5AB232EB";
      final String pexp = "010001";
      final String sexp = "0C69C84467C01B524B5942B9D76800E2D47033BDC3B5F580A879C84ED8320AB5C6C1FBE8657EA9ADFC9CF3DBF2CFEF0AF7ECA9B6828C89A0FE42CD2292AEF7F6FB0B8BC61EAE635CE3ACAADACBB0609666266D28B2760483F169C05E672C5C88D2B5B0F66C6474AA7E75A3D526EFBD865D4CD8457DD8F9D31C4B095827C6B3AD";
      final String p    = "D19916EC3E718F393467AD608813306B58F763EF6F1A8FE1251AAAE720D1A6F0E552F95DE53C0FECDFFE0ED9E541FC00F83393C9E1B26789D3A779ACA9A5C905";
      final String q    = "E0ACED5548DFF0A24147FEDE87B22505DC11FBC4F080C3E17A11BA588AE2A40AFCFDF352F9031F8F344E909C2ECCD912E2BA6B864C2DE6CFB4F50E03C17F0F2F";
      final String u    = "9EC636117E558F3A1C9E03E54A1FADD9F0A6728F34C5842B6F557D58C92BCB243FDB62AA9751B5AA24B4B5129B253ED97D3A69818C7AD2AA6483C2473C1E52F7";
      final String dp   = "9D165DC5C5AF1AA6C70E05355A06F7BD1CBA9D5DB0297A3845B4CCEDD8FD085F77A04E60FF139AE3EFA4DBC0974072FCCF08E8F4DF80F474A9FAD50881454D79";
      final String dq   = "7332D781EA1AC0A4413AAC08E7A4C4ECEB38E151CA4B0BA499D56B29A914AA2DE42845D1DE51E6A5A39940F683DC8ED4EB21D0AE0C7360AC5149710525FA830B";
      
      comp = new CryptoServerCXI.KeyComponents();
      comp.add(CryptoServerCXI.KeyComponents.TYPE_MOD, new BigInteger(mod,16));
      comp.add(CryptoServerCXI.KeyComponents.TYPE_PEXP, new BigInteger(pexp,16));
      comp.add(CryptoServerCXI.KeyComponents.TYPE_SEXP, new BigInteger(sexp,16));
      comp.add(CryptoServerCXI.KeyComponents.TYPE_P, new BigInteger(p,16));
      comp.add(CryptoServerCXI.KeyComponents.TYPE_Q, new BigInteger(q,16));
      comp.add(CryptoServerCXI.KeyComponents.TYPE_DP, new BigInteger(dp,16));
      comp.add(CryptoServerCXI.KeyComponents.TYPE_DQ, new BigInteger(dq,16));
      comp.add(CryptoServerCXI.KeyComponents.TYPE_U, new BigInteger(u,16));            
      
      rsaKey = cxi.importClearKey(CryptoServerCXI.FLAG_OVERWRITE, CryptoServerCXI.KEY_BLOB_SIMPLE, attr, comp);                 
      
      //--------------------------------------------------------------------------------
      // backup RSA key
      //--------------------------------------------------------------------------------
      CryptoServerCXI.Key key = cxi.backupKey(rsaKey);
       
      //--------------------------------------------------------------------------------
      // delete RSA key
      //--------------------------------------------------------------------------------
      cxi.deleteKey(rsaKey);
      
      //--------------------------------------------------------------------------------
      // restore RSA key
      //--------------------------------------------------------------------------------
      attr = new CryptoServerCXI.KeyAttributes();
      attr.setName("CXI_RSA_RESTORE_KEY");          
      rsaKey = cxi.restoreKey(CryptoServerCXI.FLAG_OVERWRITE, key, attr);      
            
      //--------------------------------------------------------------------------------
      // export RSA key (wrapped with AES key)
      //--------------------------------------------------------------------------------
      attr = new CryptoServerCXI.KeyAttributes();
      attr.setGroup(group);
      attr.setName("CXI_AES_IMP_KEY");
      aesKey = cxi.findKey(attr);

      attr.setName("CXI_RSA_GEN_KEY");      
      rsaKey = cxi.findKey(attr);
      
      byte [] keyBlob = cxi.exportKey(rsaKey, CryptoServerCXI.KEY_TYPE_PRIVATE, aesKey);      
      // CryptoServerUtil.xtrace("keyBlob", keyBlob);
      
      //--------------------------------------------------------------------------------
      // delete RSA key
      //--------------------------------------------------------------------------------
      cxi.deleteKey(rsaKey);
      
      //--------------------------------------------------------------------------------
      // import RSA key (wrapped with AES key)
      //--------------------------------------------------------------------------------
      attr = new CryptoServerCXI.KeyAttributes();
      attr.setGroup(group);
      attr.setName("CXI_RSA_REIMP_KEY");      
      
      rsaKey = cxi.importKey(CryptoServerCXI.FLAG_OVERWRITE, CryptoServerCXI.KEY_BLOB_SIMPLE, attr, keyBlob, aesKey);
      
      //--------------------------------------------------------------------------------
      // list keys
      //--------------------------------------------------------------------------------            
      attr = new CryptoServerCXI.KeyAttributes();
      attr.setGroup(group);
      CryptoServerCXI.KeyAttributes [] keyList = cxi.listKeys(attr);
      
      System.out.printf("\n%1$-6s %2$-8s %3$-5s %4$-24s %5$-32s %6$s\n", "algo", "type", "size", "group", "name", "specifier");
      System.out.println("-----------------------------------------------------------------------------------------");
      for (CryptoServerCXI.KeyAttributes att : keyList)
      {
        System.out.printf("%1$-6s %2$-8s %3$-5d %4$-24s %5$-32s %6$d\n", algoStrings[att.getAlgo()],
                                                                         getTypeString(att.getType()),
                                                                         att.getSize(),
                                                                         att.getGroup(), 
                                                                         att.getName(), 
                                                                         att.getSpecifier());                                                           
      } 
      
      //--------------------------------------------------------------------------------
      // delete all keys
      //--------------------------------------------------------------------------------
      System.out.println("delete all demo keys...");
      
      for (CryptoServerCXI.KeyAttributes keyattr : keyList)
      {
        key = cxi.findKey(keyattr);
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
}
