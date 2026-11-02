/**************************************************************************************************
 *
 * Filename           : property.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Property Object
 *
 *************************************************************************************************/
#ifndef CXI_API_C_PROPERTY_H_
#define CXI_API_C_PROPERTY_H_

#include "cxi.h"

namespace cxi
{
  class CXIAPI Property : public ByteArray
  {
    private:
      char *str;
      int  str_size;
      CXIAPI_LOCAL void str_alloc(const char *where, int line, int size);
      char *def_val;

    public:
      Property(void);
      Property(const char *data, int len);
      Property(const char *str);
      Property(int val, int len);
      Property(const ByteArray &ba);
      Property(const Property &prop);
      virtual ~Property(void);

      void clear(void);
      char *get(void);
      const char *get(void) const;
      char *getString(void);
      void setString(const char *str);

      // operators
      const Property &operator= (const Property &prop);
  };
}

#endif
