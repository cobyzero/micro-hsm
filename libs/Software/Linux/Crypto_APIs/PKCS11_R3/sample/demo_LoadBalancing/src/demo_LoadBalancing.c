/**
 *  \file    demo_LoadBalancing.c
 *  \brief   This file contains an assortment of functions, of which load_balancing_demo() is the most important.
 *
 *  \author  Utimaco GmbH
 *  \date    18.04.2016
 *  \version 1.0.2
 *
 *  \details The function load_balancing_demo() is called from main() with the information about the
 *           number of key generation, signing and verifying transactions to execute. In the
 *           function load_balancing_demo() PKCS#11 secure messaging sessions are opened and on each opened
 *           session a thread is started.
 *
 *           The function RSA_multi() actually performs all RSA 2084 bit
 *           transactions. It is called in each of the started threads. But the parameters handed over to
 *           RSA_multi() differ from thread to thread.
 *
 *           The function distribute_transactions() distributes
 *           the transactions on the available session in such a way that long- and short-term transactions
 *           are distributed uniformly.
 *
 *           All remaining functions are utility functions of minor importance.
 */


#include "demo_LoadBalancing.h"


/**
 *  \brief   initialization of a structure variable of type ParamRSA.
 *
 *  \return  initialized variable of type ParamRSA
 *
 *  \details Since the data to be signed or verified is kept fixed in this example,
 *           the data is assigned to the ParamRSA structure member `Data` here during initialization.
 *           See ParamRSA for more details on the other structure members.
 */
ParamRSA* newParamRSA()
{
    CK_BYTE *Data     = (CK_BYTE*) "The standard PKCS11 specifies an application programming interface (API), \n" \
                        "called Cryptoki, to devices which hold cryptographic information and perform  \n" \
                        "cryptographic functions.";
    CK_ULONG  lenData = (CK_ULONG)strlen((char*)Data);
    ParamRSA* pointer = malloc(sizeof(ParamRSA));
    memset(pointer, 0, sizeof(ParamRSA));

    memcpy(pointer->Data, Data, lenData);
    (*pointer).nK         = 0;
    (*pointer).nS         = 0;
    (*pointer).nV         = 0;
    (*pointer).session    = 0;
    (*pointer).privateKey = 0;
    (*pointer).publicKey  = 0;
    (*pointer).lenData    = lenData;
    (*pointer).pFunctions = NULL;
    return pointer;
}

/**
 *  \brief   initialization of a structure variable of type ParamLB.
 *
 *  \return  initialized variable of type ParamLB
 *
 *  \details The number of devices given in structure member `dev` will be initialized to `dev` = 1. This has
 *           the advantage that you can easily compare between different cluster sizes without worrying about
 *           exceeding the maximum number of sessions possible in a cluster (= `dev` * `max`). The member
 *           variable `max`, specifying the number of sessions per device, is set to `max` = 10 here by default.
 *           Maximum possible value for `max` is 256. For more details on the other structure members see
 *           ParamRSA.
 */
ParamLB* newParamLB()
{
    ParamLB* pointer = malloc(sizeof(ParamLB));
    memset(pointer, 0, sizeof(ParamLB));

    (*pointer).nK       = 0;
    (*pointer).nS       = 0;
    (*pointer).nV       = 0;
    (*pointer).dev      = 1; // number of devices (set to 1 for comparison reasons
    //                    between 1,2 or 3 devices)
    (*pointer).max      = 2; // maximum number of sessions per device ( no more 256 ), recommended: max = 2
    (*pointer).duration = 0;
    (*pointer).libPath  = NULL;
    return pointer;
}


#ifdef OSYS_win
/**
 *  \brief      load library, get function list, initialize token
 *
 *  \param [in] ppFunctions pointer to the PKCS#11 function pointer list
 *  \param [in] phModule pointer to the library handle
 *  \param [in] libraryPath path to the PKCS#11 dynamic link library
 *
 *  \return     exit status (zero = o.k.)
 *
 *  \details    First the PKCS#11 library, whose location is given in LibraryPath, is loaded. A pointer
 *              to the library handle is returned in phModule. A pointer to the function pointer list
 *              of all available PKCS#11 functions is returned in ppFunctions.
 */
int initialize(CK_FUNCTION_LIST_PTR_PTR ppFunctions, HMODULE* phModule, char* libraryPath, CK_BBOOL bMultiThreaded)
{
    CK_C_GetFunctionList pC_GetFunctionList = NULL;
    int                  err                = 0;

    // load PKCS#11 library
    if (((*phModule) = LoadLibrary(libraryPath)) == NULL) {
        err = GetLastError();
        printf("[initialize]: unable to load library '%s'\n", libraryPath);
        goto cleanup;
    }

    // get the address of the C_GetFunctionList function
    if ((pC_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress((*phModule), "C_GetFunctionList")) == NULL) {
        printf("[initialize]: C_GetFunctionList not found\n");
        goto cleanup;
    }

    // get addresses of all the remaining PKCS#11 functions
    err = pC_GetFunctionList(ppFunctions);
    if (err != CKR_OK) {
        printf("[initialize]: pC_GetFunctionList returned 0x%08x\n", err);
        goto cleanup;
    }

    // initialize token
    if (bMultiThreaded) {
        CK_C_INITIALIZE_ARGS initArgs;
        memset(&initArgs, 0, sizeof(initArgs));
        initArgs.flags = CKF_OS_LOCKING_OK;

        err = (*ppFunctions)->C_Initialize(&initArgs);
    } else {
        err = (*ppFunctions)->C_Initialize(NULL);
    }

    if (err != CKR_OK) {
        printf("[initialize]: C_Initialize returned 0x%08x\n", err);
        goto cleanup;
    }

cleanup:
    return err;
}
#else
/**
 *  \brief      load library, get function list, initialize token
 *
 *  \param [in] ppFunctions pointer to the PKCS#11 function pointer list
 *  \param [in] lib_handle pointer to the library handle
 *  \param [in] libraryPath path to the PKCS#11 dynamic link library
 *
 *  \return     exit status (zero = o.k.)
 *
 *  \details    First the PKCS#11 library, whose location is given in LibraryPath, is loaded. A pointer
 *              to the library handle is returned in phModule. A pointer to the function pointer list
 *              of all available PKCS#11 functions is returned in ppFunctions.
 *
 */
int initialize(CK_FUNCTION_LIST_PTR_PTR ppFunctions, void** lib_handle, char* libraryPath, CK_BBOOL bMultiThreaded)
{
    CK_C_GetFunctionList pC_GetFunctionList = NULL;
    int                  err                = 0;

    // load PKCS#11 library
    if (((*lib_handle) = dlopen(libraryPath, RTLD_LAZY)) == NULL) {
        err = CKR_FUNCTION_FAILED;
        printf("[initialize]: unable to load library '%s', dlopen returned %s\n", libraryPath, dlerror());
        goto cleanup;
    }

    // get the address of the C_GetFunctionList function
    if ((pC_GetFunctionList = (CK_C_GetFunctionList)dlsym((*lib_handle), "C_GetFunctionList")) == NULL) {
        printf("[initialize]: C_GetFunctionList not found, dlsym returned %s\n", dlerror());
        goto cleanup;
    }

    // get addresses of all the remaining PKCS#11 functions
    err = pC_GetFunctionList(ppFunctions);
    if (err != CKR_OK) {
        printf("[initialize]: pC_GetFunctionList returned 0x%08x\n", err);
        goto cleanup;
    }

    // initialize token
    if (bMultiThreaded) {
        CK_C_INITIALIZE_ARGS initArgs;
        memset(&initArgs, 0, sizeof(initArgs));
        initArgs.flags = CKF_OS_LOCKING_OK;

        err = (*ppFunctions)->C_Initialize(&initArgs);
    } else {
        err = (*ppFunctions)->C_Initialize(NULL);
    }

    if (err != CKR_OK) {
        printf("[initialize]: C_Initialize returned 0x%08x\n", err);
        goto cleanup;
    }

cleanup:
    return err;
}
#endif

/**
 *  \brief      check SO and USER existence
 *
 *  \param [in] pFunctions PKCS#11 function pointer list
 *  \param [in] userPIN PIN of cryptographic USER on slot `slotID`
 *  \param [in] lenUserPIN length of `userPIN`
 *  \param [in] slotID slot ID
 *
 *  \return     exit status (zero = o.k.)
 *
 *  \details    Checks whether an SO with PIN 12345678 and a cryptgraphic USER with PIN `userPIN`
 *              exist on slot with ID `slotID`. If this isn't the case, the function returns an error.
 */
int EnsureUserExistence(CK_FUNCTION_LIST_PTR pFunctions, CK_UTF8CHAR_PTR userPIN, CK_ULONG lenUserPIN, CK_ULONG slotID)
{
    char*             soPIN = "12345678";
    CK_TOKEN_INFO     tinfo;
    CK_ULONG          lenSoPIN = (CK_ULONG)strlen(soPIN);
    int               err      = 0;
    CK_SESSION_HANDLE hSession = 0;


    err = pFunctions->C_GetTokenInfo(slotID, &tinfo);
    if (err != CKR_OK) {
        printf("[EnsureUserExistence]: C_GetTokenInfo returned 0x%08x\n", err);
        goto cleanup;
    }


    err = pFunctions->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
    if (err != CKR_OK) {
        printf("[EnsureUserExistence]: C_OpenSession returned 0x%08x\n", err);
        goto cleanup;
    }

    // check if SO exists
    if ((tinfo.flags & CKF_TOKEN_INITIALIZED) == 0) {
        printf("[EnsureUserExistence]: SO does not exist on slot %lu.\n", slotID);
        err = CKR_GENERAL_ERROR;
        goto cleanup;
    } else {
        err = pFunctions->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)soPIN, lenSoPIN);
        if (err != CKR_OK) {
            printf("[EnsureUserExistence]: C_Login (SO) returned 0x%08x\n", err);
            goto cleanup;
        }
        err = pFunctions->C_Logout(hSession);
        if (err != CKR_OK) {
            printf("[EnsureUserExistence]: C_Logout (SO) returned 0x%08x\n", err);
            goto cleanup;
        }

        printf("-> SO with correct PIN exists on slot %lu.\n", slotID);
    }

    // check if USER exists
    if ((tinfo.flags & CKF_USER_PIN_INITIALIZED) == 0) {
        printf("[EnsureUserExistence]: USER does not exist on slot %lu.\n", slotID);
        err = CKR_GENERAL_ERROR;
        goto cleanup;
    } else {
        err = pFunctions->C_Login(hSession, CKU_USER, userPIN, lenUserPIN);
        if (err != CKR_OK) {
            printf("[EnsureUserExistence]: C_Login (USER) returned 0x%08x\n", err);
            goto cleanup;
        }
        err = pFunctions->C_Logout(hSession);
        if (err != CKR_OK) {
            printf("[EnsureUserExistence]: C_Logout (USER) returned 0x%08x\n", err);
            goto cleanup;
        }
        printf("-> USER with correct PIN exists on slot %lu.\n", slotID);
    }


cleanup:
    if (hSession != CK_INVALID_HANDLE) {
        pFunctions->C_CloseSession(hSession);
    }

    if (err != 0) {
        printf("\nRemember: Demo assumes, that\n");
        printf("                - at least one device is running\n");
        printf("                - an SO with PIN '12345678' exists on slot 0\n");
        printf("                     (true for all devices in the cluster)\n");
        printf("                - a USER with PIN '12345678' exists on slot 0\n");
        printf("                     (true for all devices in the cluster)\n\n");
    }
    return err;
}

/**
 *  \brief      get key of class `keyClass` and ID `keyID`
 *
 *  \param [in] pFunctions PKCS#11 function pointer list
 *  \param [in] hSession session handle
 *  \param [in] keyClass key class (e.g. `CKO_PRIVATE_KEY` or `CKO_PUBLIC_KEY`)
 *  \param [in] keyID key ID
 *  \param [in] lenKeyID length of `keyID`
 *  \param [in] object found key object handle
 *
 *  \return     exit status (zero = o.k.)
 *
 *  \details    This function looks for a key object of class `keyClass` and with ID `keyID` on
 *              session with handle `hSession`. In case of success, it returns the key object handle
 *              in `object`.
 */
int get_key(CK_FUNCTION_LIST_PTR pFunctions,
            CK_SESSION_HANDLE    hSession,
            CK_OBJECT_CLASS      keyClass,
            CK_BYTE*             keyID,
            size_t               lenKeyID,
            CK_OBJECT_HANDLE*    object)
{
    int err                 = 0;
    int key_not_found       = 0;
    CK_ATTRIBUTE template[] = {
      {CKA_CLASS, &keyClass, sizeof(keyClass)  },
      {CKA_ID,    keyID,     (CK_ULONG)lenKeyID}
    };
    CK_ULONG objectCount = 0;

    err = pFunctions->C_FindObjectsInit(hSession, template, 2);
    if (err != CKR_OK) {
        printf("[get_key]: C_FindObjectsInit returned 0x%08x\n", err);
        goto cleanup;
    }

    err = pFunctions->C_FindObjects(hSession, object, 1, &objectCount);
    if (err != CKR_OK) {
        printf("[get_key]:C_FindObjects returned 0x%08x\n", err);
        goto cleanup;
    }

    if (objectCount == 0) {
        switch (keyClass) {
        case CKO_PUBLIC_KEY:
            printf("-> Public key with ID %s NOT found:\n", keyID);
            break;
        case CKO_PRIVATE_KEY:
            printf("-> Private key with ID %s NOT found:\n", keyID);
            break;
        default:
            printf("-> Key with ID %s NOT found:\n", keyID);
        }
        key_not_found = 1;
    }

    err = pFunctions->C_FindObjectsFinal(hSession);
    if (err != CKR_OK) {
        printf("[get_key]: C_FindObjectsFinal returned 0x%08x\n", err);
        goto cleanup;
    }

cleanup:
    if (key_not_found != 0) {
        err = CKR_GENERAL_ERROR;
    }
    return err;
}

/**
 *  \brief      sign given data with given private key
 *
 *  \param [in] pFunctions PKCS#11 function pointer list
 *  \param [in] hSession session handle
 *  \param [in] privateKey private key handle
 *  \param [in] Data data
 *  \param [in] lenData length of data
 *  \param [in] signature pointer to signature
 *  \param [in] lenSignature pointer to length of signature
 *
 *  \return     exit status (zero = o.k.)
 *
 *  \details    On the open session with session handle `hSession` sign the data given in `Data` with
 *              the private key given in `privateKey` and return the pointer to the signature.
 *
 */
int sign_data(CK_FUNCTION_LIST_PTR pFunctions,
              CK_SESSION_HANDLE    hSession,
              CK_OBJECT_HANDLE     privateKey,
              CK_BYTE*             Data,
              CK_ULONG             lenData,
              CK_BYTE**            signature,
              CK_ULONG*            lenSignature)
{
    int          err = 0;
    CK_MECHANISM mechanism;

    if (privateKey == CK_INVALID_HANDLE) {
        printf("[sign_data]: signing impossible: invalid key handle.\n");
        err = CKR_GENERAL_ERROR;
        goto cleanup;
    }

    mechanism.mechanism      = CKM_SHA1_RSA_PKCS;
    mechanism.pParameter     = NULL;
    mechanism.ulParameterLen = 0;

    err = pFunctions->C_SignInit(hSession, &mechanism, privateKey);
    if (err != CKR_OK) {
        printf("[sign_data]: C_SignInit returned 0x%08x\n", err);
        goto cleanup;
    }

    err = pFunctions->C_Sign(hSession, Data, lenData, *signature, lenSignature);
    if (err != CKR_OK) {
        printf("[sign_data]: C_Sign (first call) returned 0x%08x\n", err);
        goto cleanup;
    }

    *signature = malloc(sizeof(unsigned char) * (*lenSignature));

    err = pFunctions->C_Sign(hSession, Data, lenData, *signature, lenSignature);
    if (err != CKR_OK) {
        printf("[sign_data]: C_Sign (second call) returned 0x%08x\n", err);
        goto cleanup;
    }

cleanup:
    return err;
}


/**
 *  \brief      search key with ID=0. If it exists, sign the data which is given in `input4RSA`.
 *
 *  \param [in] input4RSA array of ParamRSA structures, importing data to be signed and receiving signature and verfication key object (= key with ID=0)
 *  \param [in] userPIN PIN of cryptographic user
 *  \param [in] lenUserPIN length of PIN
 *  \param [in] slotID slot ID
 *  \param [in] nSessions length of `input4RSA` array above
 *
 *  \return     exit status (zero = o.k.)
 *
 *  \details    A key pair with ID=0 has to exist on slot with ID `slotID` beforehand. In this function
 *              the cryptographic USER opens a session, searches for that key pair, signs the universal
 *              data [see newParamRSA()] once and saves the signature and the key pair with ID=0 to all
 *              the `nSession` array entries of `input4RSA`.
 *
 */
int SearchKeyAndSignOnce(ParamRSA**      input4RSA,
                         CK_UTF8CHAR_PTR userPIN,
                         CK_ULONG        lenUserPIN,
                         CK_ULONG        slotID,
                         int             nSessions)
{
    CK_BYTE           keyID[sizeof(int)];
    CK_OBJECT_HANDLE  privateKey_ID0 = 0;
    CK_OBJECT_HANDLE  publicKey_ID0  = 0;
    CK_SESSION_HANDLE hSession       = 0;
    CK_BYTE*          signature      = NULL;
    CK_ULONG          lenSignature   = 0;
    int               err            = 0;
    int               i              = 0;

    // open session
    err = input4RSA[0]->pFunctions->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
    if (err != CKR_OK) {
        printf("[SearchKeyAndSignOnce]: C_OpenSession returned 0x%08x\n", err);
        goto cleanup;
    }
    err = input4RSA[0]->pFunctions->C_Login(hSession, CKU_USER, userPIN, lenUserPIN);
    if (err != CKR_OK) {
        printf("[SearchKeyAndSignOnce]: C_Login returned 0x%08x\n", err);
        goto cleanup;
    }
    // get key pair
    sprintf((char*)keyID, "%d", 0);
    err = get_key(input4RSA[0]->pFunctions, hSession, CKO_PRIVATE_KEY, keyID, 1, &privateKey_ID0);
    if (err != CKR_OK) {
        printf("[SearchKeyAndSignOnce]: get_key returned 0x%08x\n", err);
        goto cleanup;
    }
    err = get_key(input4RSA[0]->pFunctions, hSession, CKO_PUBLIC_KEY, keyID, 1, &publicKey_ID0);
    if (err != CKR_OK) {
        printf("[SearchKeyAndSignOnce]: get_key returned 0x%08x\n", err);
        goto cleanup;
    }
    err = sign_data(input4RSA[0]->pFunctions,
                    hSession,
                    privateKey_ID0,
                    input4RSA[0]->Data,
                    input4RSA[0]->lenData,
                    &signature,
                    &lenSignature);
    if (err != CKR_OK) {
        printf("[SearchKeyAndSignOnce]: sign_data returned 0x%08x\n", err);
        goto cleanup;
    }
    printf("Got RSA Key Pair with ID=0 and signed Data once.\n");
    // close session
    err = input4RSA[0]->pFunctions->C_Logout(hSession);
    if (err != CKR_OK) {
        printf("[SearchKeyAndSignOnce]: C_Logout returned 0x%08x\n", err);
        goto cleanup;
    }
    err = input4RSA[0]->pFunctions->C_CloseSession(hSession);
    if (err != CKR_OK) {
        printf("[SearchKeyAndSignOnce]: C_CloseSession returned 0x%08x\n", err);
        goto cleanup;
    }

    for (i = 0; i < nSessions; ++i) {
        input4RSA[i]->privateKey   = privateKey_ID0;
        input4RSA[i]->publicKey    = publicKey_ID0;
        input4RSA[i]->lenSignature = lenSignature;
        memcpy(input4RSA[i]->signature, signature, lenSignature);
    }

cleanup:
    if (signature != NULL) {
        free(signature);
    }
    if (err != 0) {
        printf("\nRemember: Demo assumes existing 2048 bit RSA Key pair\n");
        printf("            with ID=0 on all devices in the cluster.\n\n");
    }
    return err;
}


#ifdef OSYS_win
/**
 *  \brief      generate `nK` RSA 2048 bit key pairs, sign data `nS` times and verify `nV` times
 *
 *  \param [in] input pointer to structure of type ParamRSA
 *
 *  \return     exit status (zero = o.k.)
 *
 *  \details    This function generates `((ParamRSA*)input)->nK` times 2048 bit key pairs with ID=1. It
 *              signs `((ParamRSA*)input)->nS` times with the private key `((ParamRSA*)input)->privateKey` the data
 *              in `((ParamRSA*)input)->Data`. And it verifies  `((ParamRSA*)input)->nV` times with the
 *              public key  `((ParamRSA*)input)->publicKey` the signature `((ParamRSA*)input)->signature`.
 *
 */
int RSA_multi(LPVOID input)
#else
/**
 *  \brief      generate `nK` RSA 2048 bit key pairs, sign data `nS` times and verify `nV` times
 *
 *  \param [in] input pointer to structure of type ParamRSA
 *
 *  \return     exit status (zero = o.k.)
 *
 *  \details    This function generates `((ParamRSA*)input)->nK` times 2048 bit key pairs with ID=1. It
 *              signs `((ParamRSA*)input)->nS` times with the private key `((ParamRSA*)input)->privateKey` the data
 *              in `((ParamRSA*)input)->Data`. And it verifies  `((ParamRSA*)input)->nV` times with the
 *              public key  `((ParamRSA*)input)->publicKey` the signature `((ParamRSA*)input)->signature`.
 *
 */
void* RSA_multi(void* input)
#endif
{
    int          err = 0;
    int          i   = 0;
    CK_MECHANISM mechanism;

    CK_BYTE* signature    = NULL;
    CK_ULONG lenSignature = 0;

    CK_OBJECT_HANDLE hPublicKey  = 0;
    CK_OBJECT_HANDLE hPrivateKey = 0;

    CK_ULONG modulusBits      = 2048;
    CK_BYTE  publicExponent[] = {0x01, 0x00, 0x01};
    CK_BYTE  label[]          = {"RSA 2048 key pair"};
    CK_BYTE  keyID[]          = {"1"};
    CK_BBOOL bTrue            = CK_TRUE;

    CK_ATTRIBUTE publicKeyTemplate[] = {
      {CKA_LABEL,           label,          sizeof(label) - 1     },
      {CKA_ID,              keyID,          sizeof(keyID) - 1     },
      {CKA_TOKEN,           &bTrue,         sizeof(bTrue)         },
      {CKA_ENCRYPT,         &bTrue,         sizeof(bTrue)         },
      {CKA_VERIFY,          &bTrue,         sizeof(bTrue)         },
      {CKA_WRAP,            &bTrue,         sizeof(bTrue)         },
      {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)   },
      {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
      {CKA_LABEL,     label,  sizeof(label) - 1},
      {CKA_ID,        keyID,  sizeof(keyID) - 1},
      {CKA_TOKEN,     &bTrue, sizeof(bTrue)    },
      {CKA_PRIVATE,   &bTrue, sizeof(bTrue)    },
      {CKA_SENSITIVE, &bTrue, sizeof(bTrue)    },
      {CKA_DECRYPT,   &bTrue, sizeof(bTrue)    },
      {CKA_SIGN,      &bTrue, sizeof(bTrue)    },
      {CKA_UNWRAP,    &bTrue, sizeof(bTrue)    }
    };

    mechanism.mechanism      = CKM_SHA1_RSA_PKCS;
    mechanism.pParameter     = NULL;
    mechanism.ulParameterLen = 0;

    // VERIFY section
    if (((ParamRSA*)input)->nV > 0) {
        if (((ParamRSA*)input)->publicKey == CK_INVALID_HANDLE) {
            printf("[RSA_multi]: verification impossible - invalid key handle.\n");
            err = CKR_GENERAL_ERROR;
            goto cleanup;
        }

        for (i = 0; i < ((ParamRSA*)input)->nV; i++) {
            err = ((ParamRSA*)input)
                    ->pFunctions->C_VerifyInit(((ParamRSA*)input)->session, &mechanism, ((ParamRSA*)input)->publicKey);
            if (err != CKR_OK) {
                printf("[RSA_multi]: C_VerifyInit returned 0x%08x\n", err);
                goto cleanup;
            }

            err = ((ParamRSA*)input)
                    ->pFunctions->C_Verify(((ParamRSA*)input)->session,
                                           ((ParamRSA*)input)->Data,
                                           ((ParamRSA*)input)->lenData,
                                           ((ParamRSA*)input)->signature,
                                           ((ParamRSA*)input)->lenSignature);
            if (err != CKR_OK) {
                printf("[RSA_multi]: C_Verify returned 0x%08x\n", err);
                goto cleanup;
            }
        }
#ifdef OSYS_win
        printf("-> thread No %d finished verifying %d time/s.\n", GetCurrentThreadId(), ((ParamRSA*)input)->nV);
#else
        printf("-> thread (tid=) %lu finished verifying %d time/s.\n", pthread_self(), ((ParamRSA*)input)->nV);
#endif
    }

    // SIGN section
    if (((ParamRSA*)input)->nS > 0) {
        if (((ParamRSA*)input)->privateKey == CK_INVALID_HANDLE) {
            printf("[RSA_multi]: signing impossible - invalid key handle.\n");
            err = CKR_GENERAL_ERROR;
            goto cleanup;
        }

        err = ((ParamRSA*)input)
                ->pFunctions->C_SignInit(((ParamRSA*)input)->session, &mechanism, ((ParamRSA*)input)->privateKey);
        if (err != CKR_OK) {
            printf("[RSA_multi]: C_SignInit returned 0x%08x\n", err);
            goto cleanup;
        }

        err = ((ParamRSA*)input)
                ->pFunctions->C_Sign(((ParamRSA*)input)->session,
                                     ((ParamRSA*)input)->Data,
                                     ((ParamRSA*)input)->lenData,
                                     signature,
                                     &lenSignature);
        if (err != CKR_OK) {
            printf("[RSA_multi]: C_Sign (first call) returned 0x%08x\n", err);
            goto cleanup;
        }
        signature = malloc(sizeof(unsigned char) * lenSignature);

        for (i = 0; i < ((ParamRSA*)input)->nS; i++) {
            err = ((ParamRSA*)input)
                    ->pFunctions->C_Sign(((ParamRSA*)input)->session,
                                         ((ParamRSA*)input)->Data,
                                         ((ParamRSA*)input)->lenData,
                                         signature,
                                         &lenSignature);
            if (err != CKR_OK) {
                printf("[RSA_multi]: C_Sign (second call) returned 0x%08x\n", err);
                goto cleanup;
            }

            err = ((ParamRSA*)input)
                    ->pFunctions->C_SignInit(((ParamRSA*)input)->session, &mechanism, ((ParamRSA*)input)->privateKey);
            if (err != CKR_OK) {
                printf("[RSA_multi]: C_SignInit returned 0x%08x\n", err);
                goto cleanup;
            }
        }
#ifdef OSYS_win
        printf("-> thread No %d finished signing %d time/s.\n", GetCurrentThreadId(), ((ParamRSA*)input)->nS);
#else
        printf("-> thread (tid=) %lu finished signing %d time/s.\n", pthread_self(), ((ParamRSA*)input)->nS);
#endif
    }

    // KEY PAIR (ID=1) GENERATION section
    if (((ParamRSA*)input)->nK > 0) {
        mechanism.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;

        for (i = 0; i < ((ParamRSA*)input)->nK; i++) {
            err = ((ParamRSA*)input)
                    ->pFunctions->C_GenerateKeyPair(((ParamRSA*)input)->session,
                                                    &mechanism,
                                                    publicKeyTemplate,
                                                    sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                                    privateKeyTemplate,
                                                    sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                                    &hPublicKey,
                                                    &hPrivateKey);
            if (err != CKR_OK) {
                printf("[RSA_multi]: C_GenerateKeyPair returned 0x%08x\n", err);
                goto cleanup;
            }
        }
#ifdef OSYS_win
        printf("-> thread No %d finished generating %d key pair/s.\n", GetCurrentThreadId(), ((ParamRSA*)input)->nK);
#else
        printf("-> thread (tid=) %lu finished generating %d key pair/s.\n", pthread_self(), ((ParamRSA*)input)->nK);
#endif
    }

cleanup:
    if (signature != NULL) {
        free(signature);
    }

#ifdef OSYS_win
    return err;
#else
    ((ParamRSA*)input)->err = err;
    pthread_exit(NULL);
#endif
}


/**
 *  \brief      distribute the different types of transactions on the available sessions
 *
 *  \param [in] nSessions number of available sessions
 *  \param [in] input4RSA array of ParamRSA structures
 *  \param [in] nK number of 2048 bit RSA key pair generations
 *  \param [in] nS number of sign operations
 *  \param [in] nV number of verify operations
 *
 *  \return     exit status (zero = o.k.)
 *
 *  \details    Since Utimaco's load balancing feature is connection based and not transaction based,
 *              you either have to open and close a session for every transaction, - this only makes
 *              sense for long lasting transactions -  or you have to group or you have a software that
 *              groups the transactions in pieces of approximately same comuptation time.
 *
 *              This function here assures that the key pair generation transactions (which take
 *              from all here availabe transactions the largest amount of time) are not all grouped in one
 *              session, but are uniformly distributed over all available `nSession`. The same is
 *              assured for the number of sign and verify transactions.
 *
 */
int distribute_transactions(int nSessions, ParamRSA** input4RSA, int nK, int nS, int nV)
{
    int j;
    int err = 0;

    if (nV > 0) {
        if (nSessions == nV + nK + nS) {
            for (j = 0; j < nV; j++) {
                input4RSA[j]->nV += 1;
            }
        } else {
            if ((nV - nV % nSessions) / nSessions > 0) {
                for (j = 0; j < nSessions; j++) {
                    input4RSA[j]->nV += (nV - nV % nSessions) / nSessions;
                }
            }
            for (j = 0; j < nV % nSessions; j++) {
                input4RSA[j]->nV += 1;
            }
        }
    }

    if (nS > 0) {
        if (nSessions == nV + nK + nS) {
            for (j = nV; j < nV + nS; j++) {
                input4RSA[j]->nS += 1;
            }
        } else {
            if ((nS - nS % nSessions) / nSessions > 0) {
                for (j = 0; j < nSessions; j++) {
                    input4RSA[j]->nS += (nS - nS % nSessions) / nSessions;
                }
            }
            for (j = 0; j < nS % nSessions; j++) {
                input4RSA[j]->nS += 1;
            }
        }
    }

    if (nK > 0) {
        if (nSessions == nV + nK + nS) {
            for (j = nV + nS; j < nV + nS + nK; j++) {
                input4RSA[j]->nK += 1;
            }
        } else {
            if ((nK - nK % nSessions) / nSessions > 0) {
                for (j = 0; j < nSessions; j++) {
                    input4RSA[j]->nK += (nK - nK % nSessions) / nSessions;
                }
            }
            for (j = nSessions - 1; j > nSessions - 1 - nK % nSessions; j--) {
                input4RSA[j]->nK += 1;
            }
        }
    }

    return err;
}


#ifdef OSYS_win
/**
 *  \brief      the actual load balancing routine
 *
 *  \param [in] input pointer to a ParamLB structure
 *
 *  \return     exit status (zero = o.k.)
 *
 *  \details    This is the actual load balancing example routine. Cryptographic USER PIN is set here
 *              to 12345678 and the slot ID to zero.
 *
 *              After initialization of the token and the variables, the transactions are distributed on the
 *              available sessions through distribute_transactions(). Then it is checked that an SO and
 *              a USER both with PIN 12345678 exist on slot with ID=0 through the function EnsureUserExistence().
 *
 *              The next step is to sign the data once with the already on slot 0 existing 2048 bit RSA key and
 *              to store the public part of the key and the signature for the upcoming verification transactions.
 *              This is done in the SearchKeyAndSignOnce() function.
 *
 *              Now 'nSession' are opened. On every session a thread calling the RSA_multi() function is
 *              started with a set of key generation, sign and verify transactions to execute.
 *              The threads are running in parallel from the application point of view and Utimaco's load
 *              balancing feature assures that the sessions and with them the threads are uniformly distributed
 *              on the number of available cluster devices.
 */
int load_balancing_demo(LPVOID input)
{
    HMODULE hModule      = NULL;
    HANDLE* sInfoThreads = NULL;
    DWORD*  idThreads    = NULL;
    int     j            = 0;

#else
/**
 *  \brief      the actual load balancing routine
 *
 *  \param [in] input pointer to a ParamLB structure
 *
 *  \return     exit status (zero = o.k.)
 *
 *  \details    This is the actual load balancing example routine. Cryptographic USER PIN is set here
 *              to 12345678 and the slot ID to zero.
 *
 *              After initialization of the token and the variables, the transactions are distributed on the
 *              available sessions through distribute_transactions(). Then it is checked that an SO and
 *              a USER both with PIN 12345678 exist on slot with ID=0 through the function EnsureUserExistence().
 *
 *              The next step is to sign the data once with the already on slot 0 existing 2048 bit RSA key and
 *              to store the public part of the key and the signature for the upcoming verification transactions.
 *              This is done in the SearchKeyAndSignOnce() function.
 *
 *              Now 'nSession' are opened. On every session a thread calling the RSA_multi() function is
 *              started with a set of key generation, sign and verify transactions to execute.
 *              The threads are running in parallel from the application point of view and Utimaco's load
 *              balancing feature assures that the sessions and with them the threads are uniformly distributed
 *              on the number of available cluster devices.
 */
int load_balancing_demo(void* input)
{
    void*      lib_handle   = NULL;
    pthread_t* sInfoThreads = NULL;
    int*       pInternalErr = NULL;

#endif

    CK_FUNCTION_LIST_PTR pFunctions = NULL;

    ParamRSA** input4RSA = NULL;

    char*    userPIN    = "12345678";
    CK_ULONG lenUserPIN = (CK_ULONG)strlen(userPIN);
    CK_ULONG slotID     = 0;

    int          nSessions = 0;
    int          err       = 0;
    int          i         = 0;
    struct timeb startTime, stopTime;
    CK_BYTE      keyID[sizeof(int)];


    /* check input paramter, conclude number of sessions nSessions */
    if (((ParamLB*)input)->nK + ((ParamLB*)input)->nS + ((ParamLB*)input)->nV
        > ((ParamLB*)input)->dev * ((ParamLB*)input)->max) {
        nSessions = ((ParamLB*)input)->dev * ((ParamLB*)input)->max;
    } else {
        nSessions = ((ParamLB*)input)->nK + ((ParamLB*)input)->nS + ((ParamLB*)input)->nV;
    }

    /* initialize */
#ifdef OSYS_win
    err = initialize(&pFunctions, &hModule, ((ParamLB*)input)->libPath, (nSessions > 1));
#else
    err = initialize(&pFunctions, &lib_handle, ((ParamLB*)input)->libPath, (nSessions > 1));
#endif

    if (err != CKR_OK) {
        printf("[load_balancing_demo]: initialize returned 0x%08x\n", err);
        goto freeMemory;
    }

    /* allocate memory and initialize */
#ifdef OSYS_win
    sInfoThreads = malloc(sizeof(HANDLE) * nSessions);
    idThreads    = malloc(sizeof(DWORD) * nSessions);
    input4RSA    = malloc(nSessions * sizeof(ParamRSA*));
    for (i = 0; i < nSessions; i++) {
        input4RSA[i]             = newParamRSA();
        input4RSA[i]->pFunctions = pFunctions;
        sInfoThreads[i]          = 0;
        idThreads[i]             = 0;
    }
#else
    sInfoThreads = malloc(sizeof(pthread_t) * nSessions);
    input4RSA    = malloc(nSessions * sizeof(ParamRSA*));
    for (i = 0; i < nSessions; i++) {
        input4RSA[i]             = newParamRSA();
        input4RSA[i]->pFunctions = pFunctions;
        sInfoThreads[i]          = 0;
    }
#endif
    /*specify number and type of operation (key generation, signing, verifying) per session */
    err = distribute_transactions(
      nSessions, input4RSA, ((ParamLB*)input)->nK, ((ParamLB*)input)->nS, ((ParamLB*)input)->nV);
    if (err != 0) {
        goto freeMemory;
    }

    err = EnsureUserExistence(pFunctions, (CK_UTF8CHAR_PTR)userPIN, lenUserPIN, slotID);
    if (err != 0) {
        goto cleanup;
    }

    /* get public and private RSA key pair with ID 0 and sign Data once */

    err = SearchKeyAndSignOnce(input4RSA, (CK_UTF8CHAR_PTR)userPIN, lenUserPIN, slotID, nSessions);
    if (err != 0) {
        goto cleanup;
    }

    printf("\n... running ...\n\n");

    /* open nSession sessions and login */

    for (i = 0; i < nSessions; ++i) {
        err = pFunctions->C_OpenSession(
          slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, (CK_SESSION_HANDLE_PTR) & (input4RSA[i]->session));
        if (err != CKR_OK) {
            printf("[load_balancing_demo]: C_OpenSession returned 0x%08x\n", err);
            goto cleanup;
        }
    }
    err = pFunctions->C_Login(input4RSA[0]->session, CKU_USER, (CK_UTF8CHAR_PTR)userPIN, lenUserPIN);
    if (err != CKR_OK) {
        printf("[load_balancing_demo]: C_Login returned 0x%08x\n", err);
        goto cleanup;
    }
    for (i = 0; i < nSessions; ++i) {
        // get key pair
        sprintf((char*)keyID, "%d", 0);
        err = get_key(
          input4RSA[0]->pFunctions, input4RSA[i]->session, CKO_PRIVATE_KEY, keyID, 1, &input4RSA[i]->privateKey);
        if (err != CKR_OK) {
            printf("[load_balancing_demo]: get_key returned 0x%08x\n", err);
            goto cleanup;
        }
        err = get_key(
          input4RSA[0]->pFunctions, input4RSA[i]->session, CKO_PUBLIC_KEY, keyID, 1, &input4RSA[i]->publicKey);
        if (err != CKR_OK) {
            printf("[load_balancing_demo]: get_key returned 0x%08x\n", err);
            goto cleanup;
        }
    }

    /* do all cryptographic operations */
    ftime(&startTime);
#ifdef OSYS_win
    for (i = 0; i < nSessions; ++i) {
        if ((sInfoThreads[i] = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)RSA_multi, input4RSA[i], 0, &idThreads[i]))
            == 0) {
            err = GetLastError();
            printf("[load_balancing_demo]: CreateThread %d returned error: %d\n", i + 1, err);
            goto cleanup;
        }
        printf("-> thread No %d started.\n", idThreads[i]);
    }

    /* check threads */
    for (i = 0; i < nSessions; ++i) {
        if ((err = WaitForSingleObject(sInfoThreads[i], INFINITE)) != 0) {
            err = GetLastError();
            printf("[load_balancing_demo]: WaitForSingleObject returned error for thread %d: %d\n", i + 1, err);
            goto cleanup;
        }

        if (GetExitCodeThread(sInfoThreads[i], &j) == 0) {
            err = GetLastError();
            printf("[load_balancing_demo]: GetExitCodeThread returned error for thread %d: %d\n", i + 1, err);
            goto cleanup;
        }

        err = j ? j : err;
    }
#else
    for (i = 0; i < nSessions; ++i) {
        if ((err = pthread_create(&sInfoThreads[i], NULL, (void*)RSA_multi, (void*)input4RSA[i])) != 0) {
            printf("[load_balancing_demo]: pthread_create %d returned error: %d\n", i + 1, err);
            goto cleanup;
        }
        printf("-> %d. thread (tid=) %lu started.\n", i + 1, sInfoThreads[i]);
    }

    /* check threads */
    for (i = 0; i < nSessions; ++i) {
        if ((err = pthread_join(sInfoThreads[i], (void**)&pInternalErr)) != 0) {
            printf("[load_balancing_demo]: pthread_join returned error for thread %d: %d\n", i + 1, err);
            goto cleanup;
        }
        if (pInternalErr == PTHREAD_CANCELED) {
            printf("[load_balancing_demo]: thread %d canceled", i + 1);
        }
        err = input4RSA[i]->err ? input4RSA[i]->err : err;
    }
#endif
    ftime(&stopTime);
    ((ParamLB*)input)->duration = (unsigned long)((stopTime.time * 1000 + stopTime.millitm)
                                                  - (unsigned long)(startTime.time * 1000 + startTime.millitm));

cleanup:
    /* logout and close all session and finalize */
    if (err != 0) {
        pFunctions->C_Logout(input4RSA[0]->session);
        for (i = 0; i < nSessions; ++i) {
            if ((input4RSA[i]->session) != CK_INVALID_HANDLE) {
                pFunctions->C_CloseSession(input4RSA[i]->session);
            }
        }
    }
    pFunctions->C_Finalize(NULL);

freeMemory:
    /* free memory */
    if (sInfoThreads != NULL) {
        free(sInfoThreads);
    }
    if (input4RSA != NULL) {
        free(input4RSA);
    }

#ifdef OSYS_win
    if (idThreads != NULL) {
        free(idThreads);
    }
    if (hModule != NULL) {
        FreeLibrary(hModule);
    }
#else
    if (pInternalErr != NULL) {
        free(pInternalErr);
    }
    if (lib_handle != NULL) {
        dlclose(lib_handle);
    }
#endif


    if (err == 0) {
        return 0;
    } else {
        return err;
    }
}
