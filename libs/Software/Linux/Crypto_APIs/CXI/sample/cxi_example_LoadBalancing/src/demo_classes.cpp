/**
 *  \file    demo_classes.cpp
 *  \brief   This file contains the classes used in the demo.
 *  
 *  \author  Utimaco GmbH
 *  \date    25.01.2017
 *  \version 1.0.3
 *  
 *  \details Only two classes have been implemented. The class Request and the class Execute. The class Execute is used
 *           to process requests. The class Request contains all the information needed to unambiguosly describe a request. 
 *  
 */

#include "demo.h"


/**
 *  \brief      Constructor
 *  
 *  \param [in] requestID Request number, in order to identify the request
 *  \param [in] transaction A character describing the type of transaction. Used to select the member function to call. 
 *  \param [in] keyTemplate The template describing the key to use in the sign or verify transaction.
 *  \param [in] hash The hashed data which needs to be signed.
 *  \param [in] nr_repeats Number of times the transaction shall be repeated
 *  \param [in] signature Signature in case of `verify` transaction, otherwise skip entry
 *  
 *  \details    Creates a request with all information necessary to process it.
 */
Request::Request(int              requestID,
                 char             transaction,
                 PropertyList&    keyTemplate,
                 Hash&            hash,
                 int              nr_repeats,
                 const ByteArray& signature)
{
    b_verify_ok       = false;
    this->transaction = transaction;
    this->keyTemplate = keyTemplate;
    this->hash        = hash;
    this->signature   = signature;
    this->requestID   = requestID;
    this->nr_repeats  = nr_repeats;
}

/**
 *  \brief   Default Constructor
 *  
 *  \details Creates an "empty" object of type Request.
 */
Request::Request(void)
{
    b_verify_ok = false;
    requestID   = -1;
    nr_repeats  = 1;
}

/**
 *  \brief   Default Constructor
 *  
 *  \details Creates an "empty" object of type Execute.
 */
Execute::Execute(void)
{
#ifdef OSYS_win
    pThreadHandle = NULL;
#endif
    idThread        = 0;
    errFinishThread = 0;
    returnValue     = 0;

    bThreadExists = false;
    bRunFinished  = false;
    cxi           = NULL;
    request       = NULL;
}

/**
 *  \brief Destructor
 */
Execute::~Execute(void)
{
    int exitCode;
    finishThread(&exitCode);
}


/**
 *  \brief      Wait until the thread has finished and get the threaded function's exitCode
 *  
 *  \param [in] exitCode exit status of the function executed in the thread
 *
 *  \return     exit status of the thread  (zero = o.k.) 
 *  
 *  \details    If a thread has been started (`pThreadExists == true`) and this function hasn't yet been
 *              called and returned an error, then wait for the thread to finish and get the threaded function's exitCode.
 *              If the thread finished without error, then re-initialize the class' variables such that startThread 
 *              can be called again. 
 */
int Execute::finishThread(int* exitCode)
{
    if (bThreadExists == true && errFinishThread == 0) // test if  thread  exists
    {
        int err = 0;

#ifdef OSYS_win
        int ExitErr = 0;
        err         = WaitForSingleObject(pThreadHandle, INFINITE);
        if (err != 0) {
            printf("[Execute::finishThread] WaitForSingleObject for request %d on thread ID %d returned: %d\n",
                   this->request->requestID,
                   idThread,
                   err);
        }

        if (!GetExitCodeThread(pThreadHandle, (DWORD*)&ExitErr)) {
            int iErr = GetLastError();
            printf("[Execute::finishThread] GetExitCodeThread returned error for request %d on thread %d: %d\n",
                   this->request->requestID,
                   idThread,
                   iErr);
            err = iErr ? iErr : err;
        }
        err = (ExitErr) ? (ExitErr) : err;
        if (!CloseHandle(pThreadHandle)) {
            int iErr = GetLastError();
            printf("[Execute::finishThread] CloseHandle returned error for request %d on thread %d: %d\n",
                   this->request->requestID,
                   idThread,
                   iErr);
            err = iErr ? iErr : err;
        }
#else
        int* pExitErr = NULL;
        if ((err = pthread_join(idThread, (void**)&pExitErr)) != 0) {
            printf("[Execute::finishThread]: pthread_join returned error: %d\n", err);
        }
        if (pExitErr == PTHREAD_CANCELED) {
            printf("[Execute::finishThread]: thread canceled");
            err = ECANCELED;
        }
#endif

        if (err == 0) {
            // enable restart of new thread
#ifdef OSYS_win
            pThreadHandle = NULL;
#endif
            cxi           = NULL;
            request       = NULL;
            idThread      = 0;
            bThreadExists = false;
            bRunFinished  = false;
            (*exitCode)   = returnValue;
            returnValue   = 0;
        }
        errFinishThread = err;
    } else if (bThreadExists == false) {
        return ERR_NO_THREAD;
    }

    return errFinishThread;
}

/**
 *  \brief  Check whether thread exists, is still running or already finished
 *  
 *  \return exit status of the thread: RUN_ACTIVE=259, ERR_NO_THREAD=-13, RUN_FINISHED=261  
 */
int Execute::getThreadStatus()
{
    if (bThreadExists == true && errFinishThread == 0) {
        if (bRunFinished == true) {
            return RUN_FINISHED;
        }
        return RUN_ACTIVE;
    } else {
        return ERR_NO_THREAD;
    }
}

/**
 *  \brief      Start the thread which processes the given request
 *  
 *  \param [in] request Request to be processed
 *  \param [in] cxi CXI session/connection to use
 *  
 *  \return     exit status: o.k. (0), ERR_MISSING_SESSION (-11), ERR_ACTIVE_THREAD (-10), CreateThread()-Error 
 *  
 */
int Execute::startThread(Request* request, Cxi* cxi)
{
    if (bThreadExists == false) {
        if (request == NULL) {
            printf("[Execute::startThread] no request - thread not started.\n");
            return ERR_MISSING_SESSION;
        }
        this->request = request;

        if (cxi == NULL) {
            printf("[Execute::startThread] no secure messaging session for request %d - thread not started.\n",
                   this->request->requestID);
            return ERR_MISSING_SESSION;
        }
        this->cxi = cxi;

#ifdef OSYS_win
        if ((pThreadHandle = CreateThread(
               NULL, 0, (LPTHREAD_START_ROUTINE)staticExecuteTransaction, (void*)this, 0, &idThread))
            == 0) {
            int err = GetLastError();
            printf("[Execute::startThread] CreateThread ID=%d for request %d returned error: %d\n",
                   idThread,
                   this->request->requestID,
                   err);
            return err;
        }
        if (pThreadHandle != NULL) {
            bThreadExists = true;
        }
#else
        int err = pthread_create(&idThread, NULL, staticExecuteTransaction, (void*)this);
        if (err != 0) {
            printf("[Execute::startThread] CreateThread ID=%lu returned error: %d\n", idThread, err);
            return err;
        }
        bThreadExists = true;
#endif
    } else {
        return ERR_ACTIVE_THREAD;
    }

    return 0;
}

/**
 *  \brief      Calls the appropriate transaction function
 *  
 *  \param [in] input Parameter_Description
 *  
 *  \return     exit status (zero = o.k.)
 *  
 *  \details    A void pointer as parameter is required when creating the thread in  Execute::startThread(). 
 *              Therefore this function here is static. According to the request's transaction type, the appropriate function is
 *              called. 
 */
#ifdef OSYS_win
int Execute::staticExecuteTransaction(void* input)
#else
void* Execute::staticExecuteTransaction(void* input)
#endif
{
    int err;

    Execute* This = (Execute*)input;

    switch (This->request->transaction) {
    case 's':
    case 'S':
        err = This->Sign();
        CLEANUP(err);
        break;
    case 'v':
    case 'V':
        err = This->Verify();
        CLEANUP(err);
        break;
    default:
        printf("[Execute::staticExecuteTransaction]  transaction '%c' unknown.\n", This->request->transaction);
        CLEANUP(ERR_INPUT);
    }

cleanup:

    This->returnValue = err;

#ifdef OSYS_win
    return 0;
#else
    return NULL;
#endif
}

/**
 *  \brief   Signs hashed data.
 *  
 *  \return  exit status (zero = o.k.)
 *  
 *  \details Take all details given in the Request object (hashed data, key to use), sign the hashed data and 
 *           modify the Request object by adding the calculated signature. `bRunFinished` is set to `true` when the end
 *           of this routine is reached.
 */
int Execute::Sign()
{
    Key          key;
    PropertyList propList;
    int          err = 0;

    // find key in internal database
    try {
        int properties[] = {CXI_PROP_KEY_GROUP,
                            CXI_PROP_KEY_NAME,
                            CXI_PROP_KEY_SPEC,
                            CXI_PROP_KEY_TYPE,
                            CXI_PROP_KEY_ALGO,
                            CXI_PROP_KEY_SIZE};
        key              = cxi->key_open(0, request->keyTemplate);
        propList         = cxi->key_prop_get(key, properties, DIM(properties));
        if (propList.getAlgo() < CXI_KEY_ALGO_RSA || propList.getAlgo() > CXI_KEY_ALGO_ECDSA) {
            printf("\n[Execute::Sign] Invalid key for request %d. Supported algorithms: RSA, ECDSA\n",
                   this->request->requestID);
            CLEANUP(ERR_INVALID_KEY);
        }
    } catch (const Exception& ex) {
        printf("[Execute::Sign] Required key for request %d not found: %sat %s [%d]\n",
               this->request->requestID,
               ex.err_str,
               ex.where,
               ex.line);
        CLEANUP(ex.err);
    }

    if (propList.getAlgo() == CXI_KEY_ALGO_RSA) {
        mechParam.set(CXI_MECH_PAD_PKCS1);
    } else {
        mechParam.set(0);
    }

    // sign
    try {
        for (int i = 0; i < request->nr_repeats; i++) {
            request->signature = cxi->sign(0, key, mechParam, request->hash);
        }
    } catch (const Exception& ex) {
        printf("[Execute::Sign] sign for request %d failed: %sat %s [%d]\n",
               this->request->requestID,
               ex.err_str,
               ex.where,
               ex.line);
        CLEANUP(ex.err);
    }

cleanup:

    bRunFinished = true;
    return err;
}

/**
 *  \brief   Verifies signed hashed data.
 *  
 *  \return  exit status (zero = o.k.)
 *  
 *  \details Take all details given in the Request object (hashed data, key to use, signature) and verify the signature. 
 *           In case of success, modify the Request object by setting `b_verify_ok` to `true`. `bRunFinished` is set to `true`
 *           when the end of of this routine is reached.
 */
int Execute::Verify()
{
    Key          key;
    PropertyList propList;
    int          err = 0;

    // find key in internal database
    try {
        int properties[] = {CXI_PROP_KEY_GROUP,
                            CXI_PROP_KEY_NAME,
                            CXI_PROP_KEY_SPEC,
                            CXI_PROP_KEY_TYPE,
                            CXI_PROP_KEY_ALGO,
                            CXI_PROP_KEY_SIZE};

        key      = cxi->key_open(0, request->keyTemplate);
        propList = cxi->key_prop_get(key, properties, DIM(properties));
        if (propList.getAlgo() < CXI_KEY_ALGO_RSA || propList.getAlgo() > CXI_KEY_ALGO_ECDSA) {
            printf("\n[Execute::Verify] Invalid key for request %d. Supported algorithms: RSA, ECDSA\n",
                   this->request->requestID);
            CLEANUP(ERR_INVALID_KEY);
        }
    } catch (const Exception& ex) {
        printf("[Execute::Verify] Required key for request %d not found: %sat %s [%d]\n",
               this->request->requestID,
               ex.err_str,
               ex.where,
               ex.line);
        CLEANUP(ex.err);
    }

    if (propList.getAlgo() == CXI_KEY_ALGO_RSA) {
        mechParam.set(CXI_MECH_PAD_PKCS1);
    } else {
        mechParam.set(0);
    }

    // sign/verif
    try {
        for (int i = 0; i < request->nr_repeats; i++) {
            request->b_verify_ok = cxi->verify(0, key, mechParam, request->hash, request->signature);
        }
    } catch (const Exception& ex) {
        printf("[Execute::Verify] sign for request %d failed: %sat %s [%d]\n",
               this->request->requestID,
               ex.err_str,
               ex.where,
               ex.line);
        CLEANUP(ex.err);
    }

    if (request->b_verify_ok) {
        printf("Request %d: Verification successful.\n", this->request->requestID);
    } else {
        CLEANUP(ERR_VERIFICATION_FAILED);
    }

cleanup:

    bRunFinished = true;
    return err;
}
