/**************************************************************************************************
 *
 * Filename           : memtrace.h
 *
 * Author             : Dipl. Ing. Sven Kaltschmidt
 *                      Utimaco IS GmbH
 *
 * Description        : Memory Allocation / Tracer
 *
 *************************************************************************************************/
#ifndef __MEMTRACE_H 
#define __MEMTRACE_H 

#include "cxi.h"

namespace cxi
{
  class CXIAPI Memory
  {
    public:
      static int size(void);
      static int check(void *p_mem, const char *tag = NULL);
      
      static void *alloc(unsigned int size, const char *tag = NULL);
      static void *realloc(void *p_mem, unsigned int size, const char *tag = NULL);
      static void free(void *p_mem, const char *tag = NULL);
  };
}

#endif

