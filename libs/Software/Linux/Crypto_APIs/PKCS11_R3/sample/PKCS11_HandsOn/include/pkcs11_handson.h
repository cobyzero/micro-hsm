#ifdef OSYS_win
#include <windows.h> // used functions:  LoadLibrary(), GetProcAddress(), FreeLibrary()
#else
#include <dlfcn.h> // used functions:  dlopen(), dlsym(), dlclose()
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cryptoki.h"
#include "pkcs11t_cs.h"

#ifdef OSYS_win
int Initialize(CK_FUNCTION_LIST_PTR_PTR ppFunctions, HMODULE* phModule, char* libraryPath);
#else
int Initialize(CK_FUNCTION_LIST_PTR_PTR ppFunctions, void** lib_handle, char* libraryPath);
#endif
int EnsureUserExistence(CK_FUNCTION_LIST_PTR pFunctions, char* userPIN, CK_ULONG slotID);
int GenerateKeyPair(CK_FUNCTION_LIST_PTR pFunctions,
                    CK_SESSION_HANDLE    hSession,
                    CK_OBJECT_HANDLE_PTR phPublicKey,
                    CK_OBJECT_HANDLE_PTR phPrivateKey);
int SignData(CK_FUNCTION_LIST_PTR pFunctions,
             CK_SESSION_HANDLE    hSession,
             CK_OBJECT_HANDLE     hPrivateKey,
             CK_BYTE*             Data,
             CK_ULONG             lenData,
             CK_BYTE**            signature,
             CK_ULONG*            lenSignature);
int VerifySignedData(CK_FUNCTION_LIST_PTR pFunctions,
                     CK_SESSION_HANDLE    hSession,
                     CK_OBJECT_HANDLE     hPublicKey,
                     CK_BYTE*             Data,
                     CK_ULONG             lenData,
                     CK_BYTE*             signature,
                     CK_ULONG             lenSignature);
