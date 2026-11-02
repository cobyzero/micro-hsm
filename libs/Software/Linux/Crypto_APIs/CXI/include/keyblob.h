/**************************************************************************************************
 *
 * Filename           : blob.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Key Blob Object
 *
 *************************************************************************************************/
#ifndef SW_CXI_API_C_KEYBLOB_H
#define SW_CXI_API_C_KEYBLOB_H

#include "cxi.h"

namespace cxi
{  
  class CXIAPI KeyBlob : public ByteArray
  {    
    public:
      KeyBlob(void);
      KeyBlob(ByteArray b);
      KeyBlob(const char *data, int len);

      // set functions
      void setDES(const char *data, int len);
      void setAES(const char *data, int len);

      void setRSA
      (
        const char *mod, int l_mod,
        const char *pub, int l_pub,
        const char *p, int l_p,
        const char *q, int l_q,
        const char *dp, int l_dp,
        const char *dq, int l_dq,
        const char *u, int l_u,
        const char *prv, int l_prv
      );
      
      void setRSA
      (
        const char *mod, int l_mod,
        const char *pub, int l_pub
      );

      void setEC
      (
        const char *dp, int l_dp,
        const char *pub, int l_pub,
        const char *prv, int l_prv
      );

      void setDSA
      (
        const char *p, int l_p,
        const char *q, int l_q,
        const char *g, int l_g,
        const char *pub, int l_pub,
        const char *prv, int l_prv
      );

      // get functions
      ByteArray getProperty(int property) const;
      ByteArray getKeyComp(const char tag[]) const;
      ByteArray getPublic(void) const;
      ByteArray getPrivate(void) const;
      ByteArray getSecret(void) const;
  };
  
  // backward compatibility
  #define Blob KeyBlob
}

#endif
