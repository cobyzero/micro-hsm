/**************************************************************************************************
 *
 * Filename           : exception.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Exception Object
 *
 *************************************************************************************************/
#ifndef SW_CXI_API_XCEPTION_H_
#define SW_CXI_API_XCEPTION_H_

#include "cxi.h"

#define CXI_ERR_LEN       (256)
#define CXI_WHERE_LEN     (256)

namespace cxi
{
  class CXIAPI Exception
  {
    public:      
      int  err;       //!< error code
      char *err_str;  //!< plain text error message
      char *where;    //!< name of function where error occurs
      int  line;      //!< line number in source code
      
      Exception(const Exception& exc);
      
      Exception(const char *where, int err);
      Exception(const char *where, int line, int err);
      
      Exception(const char *where, const char *err_str);
      Exception(const char *where, int line, const char *err_str);
      Exception(const char *where, int line, int err, const char *err_str);
      
      Exception& operator=(const Exception& exc);
      
      virtual ~Exception(void);
      
      static void throwMe();

    private:
      char szerror[ CXI_ERR_LEN ];
      char szwhere[ CXI_WHERE_LEN ];
      
      CXIAPI_LOCAL void set( int err, int line, const char* pszwhere, const char* pszerror );
      CXIAPI_LOCAL void set_sz( const char *pszsrc, char *pszdst, unsigned int maxdst );
  };   
}

#endif
