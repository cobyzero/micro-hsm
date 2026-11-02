/**************************************************************************************************
 *
 * Filename           : main_3.2.1_Initialization.c
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
 * main_3.2.1
 *
 ******************************************************************************/
int main(int argc, char* argv[])
{
    CK_FUNCTION_LIST_PTR pFunctions = NULL;
#ifdef OSYS_win
    HMODULE hModule = NULL;
#else
    void* lib_handle = NULL;
#endif
    int err = 0;

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

cleanup:

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
