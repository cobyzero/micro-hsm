/**************************************************************************************************
 *
 * Filename           : keystore.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Key Store that stores external keys (Key Blobs)
 *
 *************************************************************************************************/
#ifndef SW_CXI_API_C_KEYSTORE_H
#define SW_CXI_API_C_KEYSTORE_H

#include "cxi.h"

namespace cxi
{      
  class CXIAPI KeyStore
  {
    private:
      int idx_len;
      void *p_db;
      
      CXIAPI_LOCAL void init(void);
      CXIAPI_LOCAL void open(const char *filename, int idx_len);
      
    public:
      KeyStore(void);
      KeyStore(const char *filename, int idx_len);
      KeyStore(Config &config, int idx_len);
      virtual ~KeyStore(void);

      int getIndexLength() const;
      
      /**
       * Modes for KeyStore::findKey
       */
      enum modes
      {
        MODE_EQUAL = 0, //!< search key with exactly the given index
        MODE_GTEQ,      //!< search key with the given or next greater index
        MODE_GREATER,   //!< search key with the next greater index
      };

      bool findKey(ByteArray &startIndex, int mode, PropertyList *keyTemplate = NULL);
      //deprecated overload taking optional parameter keyTemplate by reference
      bool findKey(ByteArray &startIndex, int mode, PropertyList &keyTemplate);

      Key getKey(ByteArray &index);

      void insertKey(int flags, ByteArray *index, const Key *key);
      //deprecated overloads taking optional parameters by reference
      void insertKey(int flags, ByteArray &index, const Key &key);
      void insertKey(int flags, ByteArray *index, const Key &key);

      void deleteKey(const ByteArray &index);
  };
}

#endif
