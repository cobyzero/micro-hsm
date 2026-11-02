/**************************************************************************************************
 *
 * Filename           : pkcs11_handson.c
 * Author             : Utimaco GmbH
 * Description        : PKCS#11 function collection out of the guide:
 *                      "Learning PKCS#11 in Half a Day - using the Utimaco HSM Simulator"                     
 * Creation Date      : 27.01.2016, 
 * Version            : 1.3.0
 *          
 *************************************************************************************************/

#include "pkcs11_handson.h"


/******************************************************************************
 *
 * Initialize: load library, get function list, initialize
 *
 ******************************************************************************/
#ifdef OSYS_win
int Initialize(CK_FUNCTION_LIST_PTR_PTR ppFunctions, HMODULE* phModule, char* libraryPath)
{
    CK_C_GetFunctionList pC_GetFunctionList = NULL;
    int                  err                = 0;

    // load PKCS#11 library
    if (((*phModule) = LoadLibrary(libraryPath)) == NULL) {
        err = GetLastError();
        printf("[Initialize]: unable to load library '%s'\n", libraryPath);
        goto cleanup;
    }

    // get the address of the C_GetFunctionList function
    if ((pC_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress((*phModule), "C_GetFunctionList")) == NULL) {
        printf("[Initialize]: C_GetFunctionList not found\n");
        goto cleanup;
    }
#else
int Initialize(CK_FUNCTION_LIST_PTR_PTR ppFunctions, void** lib_handle, char* libraryPath)
{
    CK_C_GetFunctionList pC_GetFunctionList = NULL;
    int                  err                = 0;

    // load PKCS#11 library
    if (((*lib_handle) = dlopen(libraryPath, RTLD_LAZY)) == NULL) {
        err = CKR_FUNCTION_FAILED;
        printf("[Initialize]: unable to load library '%s', dlsym returned: %s\n", libraryPath, dlerror());
        goto cleanup;
    }

    // get the address of the C_GetFunctionList function
    if ((pC_GetFunctionList = (CK_C_GetFunctionList)dlsym((*lib_handle), "C_GetFunctionList")) == NULL) {
        printf("[Initialize]: C_GetFunctionList not found\n");
        goto cleanup;
    }

#endif
    // get addresses of all the remaining PKCS#11 functions
    err = pC_GetFunctionList(ppFunctions);
    if (err != CKR_OK) {
        printf("[Initialize]: pC_GetFunctionList returned 0x%08x\n", err);
        goto cleanup;
    }

    // initialize token
    err = (*ppFunctions)->C_Initialize(NULL);
    if (err != CKR_OK) {
        printf("[Initialize]: C_Initialize returned 0x%08x\n", err);
        goto cleanup;
    }

cleanup:
    return err;
}


/******************************************************************************
 *
 * Check SO and USER existence -> create if necessary
 *
 ******************************************************************************/
int EnsureUserExistence(CK_FUNCTION_LIST_PTR pFunctions, char* userPIN, CK_ULONG slotID)
{
    CK_UTF8CHAR       slotLabel[32] = "PKCS11 Simulator Token";
    char*             soPIN         = "12345678";
    CK_ULONG          lenSoPIN      = (CK_ULONG)strlen(soPIN);
    CK_TOKEN_INFO     tinfo;
    char              adminPIN[100];
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
        // get default ADMIN credentials (default ADMIN key location)
        printf("-> SO does not exist on slot %lu. Slot needs to be initialized.\n\n", slotID);
        printf("=> PLEASE ENTER DEFAULT ADMIN CREDENTIALS:\n");
        printf("=> SYNTAX:  ADMIN,<path to default key file>\n");
        printf("=> EXAMPLE: ADMIN,..\\etc\\ADMIN.key\n\n");
        printf("=> PLEASE ENTER: ");
        scanf("%99s", adminPIN);
        printf("\n\n");

        // special utimaco slot initialisation with Generic user ADMIN, the CryptoServer Administrator
        err = pFunctions->C_Login(hSession, CKU_CS_GENERIC, (CK_UTF8CHAR_PTR)adminPIN, (CK_ULONG)strlen(adminPIN));
        if (err != CKR_OK) {
            printf("[EnsureUserExistence]: C_Login (ADMIN) returned 0x%08x\n", err);
            goto cleanup;
        }


        err = pFunctions->C_InitToken(slotID, (CK_UTF8CHAR_PTR)soPIN, lenSoPIN, slotLabel);
        if (err != CKR_OK) {
            printf("[EnsureUserExistence]: C_InitToken returned 0x%08x\n", err);
            goto cleanup;
        }

        err = pFunctions->C_Logout(hSession);
        if (err != CKR_OK) {
            printf("[EnsureUserExistence]: C_Logout (ADMIN) returned 0x%08x\n", err);
            goto cleanup;
        }
        printf("-> ADMIN created SO on slot %lu.\n", slotID);
    } else {
        printf("-> SO already exists on slot %lu.\n", slotID);
    }

    // check if USER exists
    if ((tinfo.flags & CKF_USER_PIN_INITIALIZED) == 0) {
        err = pFunctions->C_Login(hSession, CKU_SO, (CK_UTF8CHAR_PTR)soPIN, lenSoPIN);
        if (err != CKR_OK) {
            printf("[EnsureUserExistence]: C_Login (SO) returned 0x%08x\n", err);
            goto cleanup;
        }

        // init user pin
        err = pFunctions->C_InitPIN(hSession, (CK_UTF8CHAR_PTR)userPIN, (CK_ULONG)strlen(userPIN));
        if (err != CKR_OK) {
            printf("[EnsureUserExistence]: C_InitPIN returned 0x%08x\n", err);
            goto cleanup;
        }

        // log off SO
        err = pFunctions->C_Logout(hSession);
        if (err != CKR_OK) {
            printf("[EnsureUserExistence]: C_Logout (SO) returned 0x%08x\n", err);
            goto cleanup;
        }
        printf("-> SO created USER on slot %lu.\n", slotID);
    } else {
        printf("-> USER already exists on slot %lu.\n", slotID);
    }

    err = pFunctions->C_CloseSession(hSession);
    if (err != CKR_OK) {
        printf("[EnsureUserExistence]: C_CloseSession returned 0x%08x\n", err);
        goto cleanup;
    }

cleanup:
    return err;
}

/******************************************************************************
 *
 * Generate RSA Key Pair, 2048 bit
 *
 ******************************************************************************/
int GenerateKeyPair(CK_FUNCTION_LIST_PTR pFunctions,
                    CK_SESSION_HANDLE    hSession,
                    CK_OBJECT_HANDLE_PTR phPublicKey,
                    CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    int err = 0;

    CK_ULONG modulusBits      = 2048;
    CK_BYTE  publicExponent[] = {0x01, 0x00, 0x01};
    CK_BYTE  label[]          = {"RSA key pair"};
    CK_BYTE  keyID[]          = {"0"};
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

    CK_MECHANISM mechanism;

    mechanism.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
    mechanism.pParameter     = NULL;
    mechanism.ulParameterLen = 0;


    err = pFunctions->C_GenerateKeyPair(hSession,
                                        &mechanism,
                                        publicKeyTemplate,
                                        sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                        privateKeyTemplate,
                                        sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                        phPublicKey,
                                        phPrivateKey);
    if (err != CKR_OK) {
        printf("[GenerateKeyPair]: C_GenerateKeyPair returned 0x%08x\n", err);
        goto cleanup;
    }

    printf("-> Generated RSA %lu bit key pair with ID %s.\n", modulusBits, keyID);

cleanup:
    return err;
}

/******************************************************************************
 *
 * Sign Data
 *
 ******************************************************************************/
int SignData(CK_FUNCTION_LIST_PTR pFunctions,
             CK_SESSION_HANDLE    hSession,
             CK_OBJECT_HANDLE     hPrivateKey,
             CK_BYTE*             Data,
             CK_ULONG             lenData,
             CK_BYTE**            signature,
             CK_ULONG*            lenSignature)
{
    int          err = 0;
    CK_MECHANISM mechanism;

    if (hPrivateKey == CK_INVALID_HANDLE) {
        printf("[SignData]: signing impossible: invalid key handle.\n");
        err = 1;
        goto cleanup;
    }

    mechanism.mechanism      = CKM_SHA256_RSA_PKCS;
    mechanism.pParameter     = NULL;
    mechanism.ulParameterLen = 0;

    err = pFunctions->C_SignInit(hSession, &mechanism, hPrivateKey);
    if (err != CKR_OK) {
        printf("[SignData]: C_SignInit returned 0x%08x\n", err);
        goto cleanup;
    }

    err = pFunctions->C_Sign(hSession, Data, lenData, NULL, lenSignature);
    if (err != CKR_OK) {
        printf("[SignData]: C_Sign (first call) returned 0x%08x\n", err);
        goto cleanup;
    }
    *signature = (CK_BYTE_PTR)malloc(sizeof(CK_BYTE) * (*lenSignature));

    err = pFunctions->C_Sign(hSession, Data, lenData, *signature, lenSignature);
    if (err != CKR_OK) {
        printf("[SignData]: C_Sign (second call) returned 0x%08x\n", err);
        goto cleanup;
    }

    printf("-> Signed data successfully.\n");

cleanup:
    return err;
}

/******************************************************************************
 *
 * Verify Signed Data
 *
 ******************************************************************************/
int VerifySignedData(CK_FUNCTION_LIST_PTR pFunctions,
                     CK_SESSION_HANDLE    hSession,
                     CK_OBJECT_HANDLE     hPublicKey,
                     CK_BYTE*             Data,
                     CK_ULONG             lenData,
                     CK_BYTE*             signature,
                     CK_ULONG             lenSignature)
{
    int          err = 0;
    CK_MECHANISM mechanism;

    mechanism.mechanism      = CKM_SHA256_RSA_PKCS;
    mechanism.pParameter     = NULL;
    mechanism.ulParameterLen = 0;

    if (hPublicKey == CK_INVALID_HANDLE) {
        printf("[VerifySignedData]: verification impossible - invalid key handle.\n");
        err = 1;
        goto cleanup;
    }

    err = pFunctions->C_VerifyInit(hSession, &mechanism, hPublicKey);
    if (err != CKR_OK) {
        printf("[VerifySignedData]: C_VerifyInit returned 0x%08x\n", err);
        goto cleanup;
    }

    err = pFunctions->C_Verify(hSession, Data, lenData, signature, lenSignature);
    if (err != CKR_OK) {
        printf("[VerifySignedData]: C_Verify returned 0x%08x\n", err);
        goto cleanup;
    }

    printf("-> Verified data successfully.\n");

cleanup:
    return err;
}
