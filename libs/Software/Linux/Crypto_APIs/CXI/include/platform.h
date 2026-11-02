
/******************************************************************************
 *
 * OSYS_STR
 *
 ******************************************************************************/
#ifdef OSYS_win
  #define OSYS_STR "win"
#endif

#ifdef OSYS_Linux
  #define OSYS_STR "Linux"
#endif

#ifdef OSYS_SunOS
  #define OSYS_STR "SunOS"
#endif

#ifdef OSYS_AIX
  #define OSYS_STR "AIX"
#endif

#ifdef OSYS_OpenBSD
  #define OSYS_STR "OpenBSD"
#endif

#ifdef OSYS_FreeBSD
  #define OSYS_STR "FreeBSD"
#endif

#ifndef OSYS_STR
  #define OSYS_STR ""
#endif
  
/******************************************************************************
 *
 * ARCH_STR
 *
 ******************************************************************************/
#ifdef ARCH_x64
  #define ARCH_STR "-x64"
#endif

#ifdef ARCH_x86
  #define ARCH_STR "-x86"
#endif

#ifdef ARCH_x86_64
  #define ARCH_STR "-x86_64"
#endif

#ifdef ARCH_i686
  #define ARCH_STR "-i686"
#endif

#ifdef ARCH_i386
  #define ARCH_STR "-i386"
#endif

#ifdef ARCH_powerpc
  #define ARCH_STR "-powerpc"
#endif

#ifdef ARCH_ppc32
  #define ARCH_STR "-ppc32"
#endif

#ifdef ARCH_ppc64
  #define ARCH_STR "-ppc64"
#endif

#ifdef ARCH_sparc
  #define ARCH_STR "-sparc"
#endif

#ifndef ARCH_STR
  #define ARCH_STR ""
#endif

/******************************************************************************
 *
 * CFG_STR
 *
 ******************************************************************************/
#ifdef DEBUG
  #define CFG_STR "-dbg"
#else
  #define CFG_STR ""  
#endif
