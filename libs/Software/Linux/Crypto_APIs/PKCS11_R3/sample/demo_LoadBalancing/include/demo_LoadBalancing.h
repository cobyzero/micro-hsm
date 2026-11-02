/**
 *  \file  demo_LoadBalancing.h
 *  \brief corresponding header file to demo_LoadBalancing.c 
 */

#ifdef OSYS_win
#include <windows.h>
#include <io.h>
#include <malloc.h>
#else
#include <dlfcn.h>
#include <pthread.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/timeb.h>

#include "cryptoki.h"
#include "pkcs11t_cs.h"


/******************************************************************************
 *
 * Structures 
 *
 ******************************************************************************/

/**
 *  \struct ParamLB
 *  \brief  Structure grouping parameters to be handed over from main() to the load_balancing_demo() function 
 */
typedef struct {
    int nK; ///< `nK` receives the number of RSA 2084 bit key pair generations from the command-line
    int nS; ///< `nS` receives the number of signing transactions from the command-line
    int nV; ///< `nV` receives the number of verifying transactions from thecommand-line
    int
      dev; ///< In `dev` the number of devices can be set. It is only used to calculate the maximum number of session (= dev * max) which can be opened. [Default value is `dev` = 1, see newParamLB()]
    int
      max; ///< In `max` the number of sessions per device can be specified. It is limited to 256 per device. But keep in mind, that `max` greater than 2 does in general not increase performance [increase cluster size to increase performance]
    long duration; ///< `duration` is used to return the time needed to perform all transactions.
    char*
      libPath; ///<  `libPath` contains the path to the PKCS#11 dynamic link library file as entered on the command-line
} ParamLB;


/**
 *  \struct ParamRSA
 *  \brief Structure grouping parameters to be handed over to the RSA_multi() function 
 */
typedef struct {
    CK_SESSION_HANDLE session;    ///< session handle
    int               nK;         ///< number of key generations
    int               nS;         ///< number of signing transactions
    int               nV;         ///< number of verifying transactions
    CK_OBJECT_HANDLE  publicKey;  ///< RSA 2048 bit public key handle
    CK_OBJECT_HANDLE  privateKey; ///< RSA 2048 bit private key handle
    CK_BYTE           Data
      [1024]; ///< data to be signed or verified. In the example this data is the same for all transactions [see newParamLB()].
    CK_ULONG             lenData;         ///< length of data
    CK_BYTE              signature[1024]; ///< signature
    CK_ULONG             lenSignature;    ///< length of signature
    CK_FUNCTION_LIST_PTR pFunctions;      ///< pointer to PKCS#11 function list
#ifndef OSYS_win
    int err;
#endif
} ParamRSA;


/******************************************************************************
 *
 * Functions 
 *
 ******************************************************************************/

ParamRSA* newParamRSA();
ParamLB*  newParamLB();

#ifdef OSYS_win

int initialize(CK_FUNCTION_LIST_PTR_PTR ppFunctions, HMODULE* phModule, char* libraryPath, CK_BBOOL bMultiThreaded);

int RSA_multi(LPVOID input);
int load_balancing_demo(LPVOID input);

#else

int initialize(CK_FUNCTION_LIST_PTR_PTR ppFunctions, void** lib_handle, char* libraryPath, CK_BBOOL bMultiThreaded);

void* RSA_multi(void* input);
int   load_balancing_demo(void* input);

#endif

int EnsureUserExistence(CK_FUNCTION_LIST_PTR pFunctions, CK_UTF8CHAR_PTR userPIN, CK_ULONG lenUserPIN, CK_ULONG slotID);

int get_key(CK_FUNCTION_LIST_PTR pFunctions,
            CK_SESSION_HANDLE    session,
            CK_OBJECT_CLASS      keyClass,
            CK_BYTE*             keyID,
            size_t               lenKeyID,
            CK_OBJECT_HANDLE*    object);

int sign_data(CK_FUNCTION_LIST_PTR pFunctions,
              CK_SESSION_HANDLE    session,
              CK_OBJECT_HANDLE     privateKey,
              CK_BYTE*             Data,
              CK_ULONG             lenData,
              CK_BYTE**            signature,
              CK_ULONG*            lenSignature);

int SearchKeyAndSignOnce(ParamRSA**      input4RSA,
                         CK_UTF8CHAR_PTR userPIN,
                         CK_ULONG        lenUserPIN,
                         CK_ULONG        slotID,
                         int             nSessions);


int distribute_transactions(int nSessions, ParamRSA** input4RSA, int nK, int nS, int nV);
