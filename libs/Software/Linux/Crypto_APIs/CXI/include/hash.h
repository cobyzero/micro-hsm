/**************************************************************************************************
 *
 * Filename           : hash.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Hash Creation
 *
 *************************************************************************************************/
#ifndef CXI_API_C_HASH_H_
#define CXI_API_C_HASH_H_

#include "cxi.h"

namespace cxi
{
  class CXIAPI Hash : public ByteArray
  {
    private:
      int  hash_algo;
      std::vector<unsigned char> hash_info;

    public:
      Hash(void);
      Hash(int algo);
      virtual ~Hash(void);

      void init(int algo);
      void update(const char *data, int len);
      void update(const ByteArray &data);
      void final(void);
  };
}

#endif
