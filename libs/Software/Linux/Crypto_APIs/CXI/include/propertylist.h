/**************************************************************************************************
 *
 * Filename           : propertylist.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Encapsulates Array of Property Objects
 *
 *************************************************************************************************/
#ifndef SW_CXI_API_C_PROPERTYLIST_H_
#define SW_CXI_API_C_PROPERTYLIST_H_

#include "cxi.h"

namespace cxi
{
  class CXIAPI PropertyList
  {
    private:
      Property proptab[128];
    public:
      int getMaxProperties(void) const { return sizeof(proptab)/sizeof(proptab[0]); }

      PropertyList(void);
      PropertyList(unsigned char *p_data, unsigned int l_data);
      PropertyList(const ByteArray &data);
      PropertyList(const PropertyList &pl);
      virtual ~PropertyList(void);

      void clear(void);
      void parse(const unsigned char *p_data, unsigned int l_data);
      void parse(const ByteArray &pl);
      void merge(const PropertyList &pl);
      ByteArray serialize(void) const;

      static ByteArray find(int idx, const ByteArray &pl);

      // get property values      
      const Property &get(int idx) const;

      int    getAlgo(void) const;
      int    getSize(void) const;
      char   *getCurve(void);
      char   *getGroup(void);
      char   *getName(void);
      int    getExport(void) const;
      int    getUsage(void) const;
      int    getSpecifier(void) const;
      char   *getLabel(void);
      int    getBlockLength(void) const;
      int    getType(void) const;
      char   *getDate(void);
      char   *getDateGen(void);
      char   *getDateExp(void);
      time_t getTime(void);
      time_t getTimeGen(void);
      time_t getTimeExp(void);

      ByteArray getUName(void);
      const Property &getMechs(void) const;
      int getFipsUsage(void) const;

      // set property values
      void  set(int idx, const Property &property);

      void  setAlgo(int algo);
      void  setSize(int size);
      void  setCurve(const char *curve);
      void  setGroup(const char *group); 
      void  setName(const char *name);
      void  setExport(int expo);
      void  setUsage(int usage);
      void  setSpecifier(int spec);
      void  setLabel(const char *label);
      void  setType(int type);
      void  setDate(const char *date);
      void  setDateGen(const char *date);
      void  setDateExp(const char *date);
      void  setTime(time_t timer);
      void  setTimeGen(time_t timer);
      void  setTimeExp(time_t timer);
      void  setMechs(int *mechs, int len);
      void  setFipsUsage(int usage);

      // overloaded operators
      const PropertyList &operator=(const PropertyList &pl);
      const PropertyList &operator|=(const PropertyList &pl);
  };
}

#endif
