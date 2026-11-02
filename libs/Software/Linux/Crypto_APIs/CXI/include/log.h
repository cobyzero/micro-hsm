/**************************************************************************************************
 *
 * Filename           : log.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Logging Functions
 *
 *************************************************************************************************/
#ifndef CXI_API_C_LOG_H_
#define CXI_API_C_LOG_H_

#include <stdarg.h>

#include <cs_mutex.h>

#include "cxi.h"

#ifdef USE_DEPRECATED
  // use enum values instead
  #define LOG_LEVEL_NONE        0
  #define LOG_LEVEL_ERROR       1
  #define LOG_LEVEL_WARNING     2
  #define LOG_LEVEL_INFO        3
  #define LOG_LEVEL_TRACE       4
  #define LOG_LEVEL_DEBUG       5
#endif

namespace cxi
{    
  class CXIAPI Log
  {
    private:    
      char     filename[640];
      int      size;
      int      level;
      CS_Mutex mFileAccess;
      
      CXIAPI_LOCAL void setFilePermissions(void);
      CXIAPI_LOCAL void fileWrite(const char* time, unsigned int processid, unsigned int threadid, const char* where, const char* msg);
      CXIAPI_LOCAL void fileWriteHex(const char* time, unsigned int processid, unsigned int threadid, const char* where, const char* text, const char *data, int len);
      CXIAPI_LOCAL FILE *open(void);
      CXIAPI_LOCAL static int getLevel(const char *format);
    
    protected:
      void vprint(const char *where, int line, const char *format, va_list args);
    
    public:
      /**
       * Log Level
       */
      enum levels
      {
        LEVEL_NONE = 0,   //!< disable logging
        LEVEL_ERROR,      //!< log only errors
        LEVEL_WARNING,    //!< log errors and warnings
        LEVEL_INFO,       //!< log errors, warnings and informational messages
        LEVEL_TRACE,      //!< additionally log trace output (usually only for diagnostic purposes)
        LEVEL_DEBUG       //!< additionally log debug output (usually only during development)
      };
      
      Log(char *filename = NULL, int level = Log::LEVEL_NONE, int size = 0);
      Log(const Log &log);
      Log(Config &config);
      
      void init(const char *filename = NULL, int level = Log::LEVEL_NONE, int size = 0);
	  void init(Config &config);

      void print(const char *where, const char *format,... );
      void print(const char *where, int line, const char *format,... );

      void xprint(const char *where, const char *text, const char *data, int len);
      void xprint(const char *where, const char *text, const ByteArray &ba);

      static Log &getInstance(void);
  };
}

#endif
