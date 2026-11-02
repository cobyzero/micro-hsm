/**************************************************************************************************
 *
 * Filename           : util.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Utility Functions
 *
 *************************************************************************************************/
#ifndef __UTIL_H
#define __UTIL_H

#include "cxi.h"

/******************************************************************************
 *
 * Macros
 *
 ******************************************************************************/
#ifndef MIN
#define MIN(a,b)   ((a)<(b)?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b)   ((a)>(b)?(a):(b))
#endif

#ifdef OSYS_win
#define GMTIME(a,b) gmtime_s(b,a)
#define LOCALTIME(a,b) localtime_s(b,a)
#else
#define GMTIME(a,b) gmtime_r(a,b)
#define LOCALTIME(a,b) localtime_r(a,b)
#endif

namespace cxi
{
  class CXIAPI Util
  {
    public:
      static void store_int2(unsigned int val, unsigned char *buf);
      static void store_int3(unsigned int val, unsigned char *buf);
      static void store_int4(unsigned int val, unsigned char *buf);

      static unsigned int load_int2(const unsigned char *buf);
      static unsigned int load_int3(const unsigned char *buf);
      static unsigned int load_int4(const unsigned char *buf);

      static char *rtrim(char *s, char c);

      static void xtrace(FILE *fp, const char *prefix, const char *text, const void *data, int len);
      static void xtrace(const char *text, const void *data, int len);
      static void xtrace(const char *text, const ByteArray &ba);
  };
}

#endif
