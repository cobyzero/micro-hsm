/**
 *  \file  demo.h
 *  \brief header file for demo_functions.cpp, demo_classes.cpp and demo_main.cpp 
 */

#ifdef OSYS_win
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#define strncasecmp _strnicmp
#pragma warning(disable : 4786)
#else
#include <errno.h>
#include <dlfcn.h>
#include <time.h>
#include <pthread.h>
#define MAX_PATH 260
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifndef NOHAVE_MALLOC_H
#include <malloc.h>
#endif
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <queue>
#include <sys/timeb.h>
#include <math.h>

#include <cxi.h>

using namespace cxi;
using namespace std;

/******************************************************************************
 *
 * Definitions - Constants
 *
 ******************************************************************************/

#define SESSIONS_PER_HSM 2 ///< number of sessions per HSM [0 < integer < 257]


#define RUN_ACTIVE   259
#define RUN_FINISHED 261

/******************************************************************************
 *
 * Definitions - Error Codes
 *
 ******************************************************************************/

#define ERR_CRITICAL_SECTION -1

#define ERR_ACTIVE_THREAD       -10
#define ERR_MISSING_SESSION     -11
#define ERR_INPUT               -12
#define ERR_NO_THREAD           -13
#define ERR_VERIFICATION_FAILED -14

#define ERR_MAX_CONTAINERSIZE -17
#define ERR_FINISH_THREAD     -18
#define ERR_EXECUTE_REQUEST   -19
#define ERR_GET_THREAD_INFO   -20
#define ERR_INVALID_KEY       -21

/******************************************************************************
 *
 * Definitions - Macros
 *
 ******************************************************************************/

/**
 *  \def CLEANUP
 *  \brief used for error handling
 */
#define CLEANUP(e)    \
    {                 \
        err = (e);    \
        goto cleanup; \
    }
/**
 *  \def ENDUP
 *  \brief used for error handling
 */
#define ENDUP(e)   \
    {              \
        err = (e); \
        goto end;  \
    }
/**
 *  \def DIM
 *  \brief get size of an array
 */
#define DIM(x) (sizeof((x)) / sizeof((x[0])))

/******************************************************************************
 *
 * Classes
 *
 ******************************************************************************/

/**
 *   \class Request 
 *   \brief describes unambiguouslya request
 */
class Request
{
public:
    Request(int              requestID,
            char             transaction,
            PropertyList&    keyTemplate,
            Hash&            hash,
            int              nr_repeats,
            const ByteArray& signature = ByteArray());
    Request();

    bool         b_verify_ok;
    char         transaction;
    PropertyList keyTemplate;
    Hash         hash;
    ByteArray    signature;
    int          requestID;
    int          nr_repeats;
};

/**
 *   \class Execute 
 *   \brief unambiguously describe a request
 */
class Execute
{
public:
    Execute(void);
    ~Execute(void);

    int getThreadStatus();
    int startThread(Request* request, Cxi* cxi);
    int finishThread(int* exitCode);

private:
    int Sign();
    int Verify();
#ifdef OSYS_win
    static int staticExecuteTransaction(void* input);
#else
    static void* staticExecuteTransaction(void* input);
#endif

    Cxi*     cxi;
    Request* request;

    MechanismParameter mechParam;

#ifdef OSYS_win
    HANDLE pThreadHandle;
    DWORD  idThread;
#else
    pthread_t idThread;
#endif
    int  errFinishThread;
    bool bThreadExists;
    bool bRunFinished;
    int  returnValue;
};


/******************************************************************************
 *
 * Structures
 *
 ******************************************************************************/

/**
 *  \struct HandoverStruct
 *  \brief  Structure grouping parameters to be handed over to the ReceivingRequests() function 
 */
struct HandoverStruct {
    std::queue<Request>* requests; ///< request container
    string               group;    ///< group name
    string               keyName;  ///< key name used to sign (or verify)

    string distribution_type;  ///< type of delay time distribution between consecutive requests
    int    distribution_mean;  ///< mean of the delay time distribution
    int    nr_requests;        ///< total number of requests to process
    int    nr_repeats;         ///< number of times the transaction shall be repeated
    int*   factor;             ///< allows the transaction repeats to vary
    size_t N;                  ///< number of different transaction repeats
    bool   bReceptionFinished; ///< set to true if all request have been received

#ifdef OSYS_win
    CRITICAL_SECTION* pCriticalSection; ///< critical section pointer
#else
    pthread_mutex_t* pMutex; ///< pthread mutex pointer
#endif
    unsigned long starttime;        ///< time request receipt started
    unsigned int  maxContainerSize; ///< maximum request container size
};


/******************************************************************************
 *
 * Functions
 *
 ******************************************************************************/

#ifdef OSYS_win
int receivingRequests(void* input);
#else
void* receivingRequests(void* input);
#endif
void removeSurroundingWhitespaces(string& s);
int  parseConfigFile(char* cfgfile, string& cxifile, HandoverStruct* input, string& user, string& pwd, string& method);
