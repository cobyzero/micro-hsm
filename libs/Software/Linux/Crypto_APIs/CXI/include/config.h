/**************************************************************************************************
 *
 * Filename           : config.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Configuration Object / Parser
 *
 *************************************************************************************************/
#ifndef SW_CXI_API_C_CONFIG_H_
#define SW_CXI_API_C_CONFIG_H_

#ifdef _MSC_VER
  #pragma warning (disable: 4786)
  #pragma warning (disable: 4251)
#endif

#include <vector>
#include <string>
#include <map>

#include "cxi.h"

namespace cxi
{    
  class CXIAPI Config
  {    
    private:
      std::map<std::string,ByteArray> items;

      CXIAPI_LOCAL void parse(std::string filename);

    public:      
      Config(void);
      Config(std::string filename);
            
      void dump(void);
      bool exist(std::string key) const;
      
      void add(std::string key, const ByteArray &value);
      void addString(std::string key, std::string value);
      void addInt(std::string key, int value);
      
      ByteArray   get(std::string key, ByteArray def) const;
      std::string getString(std::string key, std::string def);
      int         getInt(std::string key, int def);
      
      std::vector<std::string> getStringValues(std::string key) const;
  };
}

#endif
