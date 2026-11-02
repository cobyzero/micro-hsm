/**************************************************************************************************
 *
 * Filename           : item.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Parse / Construct command items and property lists
 *
 *************************************************************************************************/
#ifndef CXI_API_C_ITEM_H_C
#define CXI_API_C_ITEM_H_C

#include "cxi.h"

namespace cxi
{  
  class CXIAPI Item : public ByteArray
  {
    public:
      Item(void);
      Item(const ByteArray &data);
      Item(const char *p_data, int l_data);
      Item(const char tag[], const ByteArray &value);

      ByteArray getValue(void);
      Item find(const char tag[]);
      bool exists(const char tag[]) const;

      // static members used to parse item lists
      static Item find(const char tag[], const unsigned char *p_data, unsigned int l_data, int idx = 0);
      static Item find(const char tag[], const ByteArray &data, int idx = 0);
      
      static ByteArray findValue(const char tag[], const unsigned char *p_data, unsigned int l_data, int idx = 0);
      static ByteArray findValue(const char tag[], const ByteArray &data, int idx = 0);

      static unsigned int getLength(const char tag[], const unsigned char *p_data, unsigned int l_data, int idx = 0);
      static unsigned int getLength(const char tag[], const ByteArray &data, int idx = 0);
  };
}

#endif
