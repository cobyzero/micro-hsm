/**************************************************************************************************
 *
 * Filename           : keylist.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Encapsulates array of Key Objects
 *
 *************************************************************************************************/
#ifndef SW_CXI_API_C_KEYLIST_H
#define SW_CXI_API_C_KEYLIST_H

#ifdef _MSC_VER
  #pragma warning (disable: 4251)
#endif

#include <vector>

#include "cxi.h"

namespace cxi
{ 
  class CXIAPI KeyList
  {
    private:
      std::vector<PropertyList> list;

    public:
      int size(void) const;
      void add(const PropertyList &pl);
      void sort(void);

      PropertyList &operator[](int i);
      const PropertyList &operator[](int i) const;
  };
}

#endif
