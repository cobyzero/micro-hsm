/**************************************************************************************************
 *
 * Filename           : main_3.3.3_GenerateKeyPair.c
 * Author             : Utimaco GmbH
 * Description        : PKCS#11 main example out of the guide:
 *                      "Learning PKCS#11 in Half a Day - using the Utimaco HSM Simulator"
 * Dependencies       : pkcs11_handson.c 
 * Creation Date      : 27.01.2016
 * Version            : 1.3.0
 *
 *************************************************************************************************/

#include "pkcs11_handson.h"

/******************************************************************************
 *
 * main_3.3.3
 *
 ******************************************************************************/
int main(int argc, char* argv[])
{
    int err = 0;

    CK_FUNCTION_LIST_PTR pFunctions = NULL;
#ifdef OSYS_win
    HMODULE hModule = NULL;
#else
    void* lib_handle = NULL;
#endif

    char*    userPIN    = "12345678";
    CK_ULONG lenUserPIN = (CK_ULONG)strlen(userPIN);
    CK_ULONG slotID     = 0;

    CK_SESSION_HANDLE hSession    = 0;
    CK_OBJECT_HANDLE  hPublicKey  = 0;
    CK_OBJECT_HANDLE  hPrivateKey = 0;

    // initialize
    if (argc == 3) {
        if (strcmp(argv[1], "-LIB") == 0 && argc == 3) {
#ifdef OSYS_win
            err = Initialize(&pFunctions, &hModule, argv[2]);
#else
            err = Initialize(&pFunctions, &lib_handle, argv[2]);
#endif
            if (err != 0) {
                goto cleanup;
            }
            printf("Token initialized.\n\n");
        } else {
            goto syntax;
        }
    } else {
        goto syntax;
    }

    // check for users on slot 0
    err = EnsureUserExistence(pFunctions, userPIN, slotID);
    if (err != 0) {
        goto cleanup;
    }

    // open session
    err = pFunctions->C_OpenSession(slotID, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &hSession);
    if (err != CKR_OK) {
        printf("[main]: C_OpenSession returned 0x%08x\n", err);
        goto cleanup;
    }
    printf("\nOpened session on slot %lu.\n", slotID);

    // login as user
    err = pFunctions->C_Login(hSession, CKU_USER, (CK_UTF8CHAR_PTR)userPIN, lenUserPIN);
    if (err != CKR_OK) {
        printf("[main]: C_Login (USER) returned 0x%08x\n", err);
        goto cleanup;
    }
    printf("-> Normal user logged in.\n");

    // generate 2048 bit RSA key pair and return keys
    err = GenerateKeyPair(pFunctions, hSession, &hPublicKey, &hPrivateKey);
    if (err != 0) {
        goto cleanup;
    }

    // logout
    err = pFunctions->C_Logout(hSession);
    if (err != CKR_OK) {
        printf("[main]: C_Logout (USER) returned 0x%08x\n", err);
        goto cleanup;
    }
    printf("-> Normal user logged out.\n");

    // close session
    err = pFunctions->C_CloseSession(hSession);
    if (err != CKR_OK) {
        printf("[main]: C_CloseSession returned 0x%08x\n", err);
        goto cleanup;
    }
    printf("Closed session on slot %lu.\n\n", slotID);

cleanup:

    if (err != 0 && hSession != CK_INVALID_HANDLE) {
        pFunctions->C_Logout(hSession);
        pFunctions->C_CloseSession(hSession);
    }
    if (pFunctions != NULL) {
        pFunctions->C_Finalize(NULL);
        printf("\nToken finalized.\n");
    }
#ifdef OSYS_win
    if (hModule != NULL) {
        FreeLibrary(hModule);
    }
#else
    if (lib_handle != NULL) {
        dlclose(lib_handle);
    }
#endif
    return err;

syntax:
    printf("\n[main] : syntax error !\n");
#ifdef OSYS_win
    printf("\nSYNTAX: %s -LIB <library path>\\cs_pkcs11_R3.dll\n\n", argv[0]);
#else
    printf("\nSYNTAX: %s -LIB <libary path>/libcs_pkcs11_R3.so\n\n", argv[0]);
#endif
    return err;
}
