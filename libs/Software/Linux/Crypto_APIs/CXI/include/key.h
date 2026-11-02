/**************************************************************************************************
 *
 * Filename           : key.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : CXI Key Object
 *
 *************************************************************************************************/
#ifndef SW_CXI_API_C_KEY_H_
#define SW_CXI_API_C_KEY_H_

#include "cxi.h"

namespace cxi
{  
  class CXIAPI Key : public ByteArray
  {    
    private:
      CXIAPI_LOCAL Item getKeyBlob() const;

    public:
      Key(void);
      Key(const ByteArray& b);
      Key(const char *data, int len);

      /**
       * Key Types
       */
      enum types
      {
        TYPE_UNKNOWN = 0, //!< unknown key type
        TYPE_HANDLE,      //!< key handle: reference to internal key stored on CryptoServer
        TYPE_BLOB         //!< key blob: external key (encrypted with the CryptoServer's MBK)
      };
      
      int           getType() const;
      ByteArray     getUName() const;

      PropertyList  getProplist() const;
      ByteArray     getPublicKey() const;
  };
}

#endif
