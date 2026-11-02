/**
 *  \file  example_ops.cpp
 *  \brief Exemplary cryptographic operations for demo_MultiThreading
 */

#include "demo_MultiThreading.h"

CK_OBJECT_HANDLE generate_rsa_key_pair(CK_SESSION_HANDLE hSession)
{
    CK_OBJECT_HANDLE pubKey = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE prvKey = CK_INVALID_HANDLE;

    CK_BBOOL    bTrue        = CK_TRUE;
    CK_BBOOL    bFalse       = CK_FALSE;
    CK_BYTE     keyID[]      = "0";
    CK_BYTE     prv_label[]  = "private RSA Key";
    CK_BYTE     pub_label[]  = "public RSA Key";
    CK_ULONG    modulus_bits = 2048;
    CK_KEY_TYPE keyType      = CKK_RSA;

    CK_ATTRIBUTE publicKeyTemplate[] = {
      {CKA_LABEL,        pub_label,     sizeof(pub_label) - 1},
      {CKA_TOKEN,        &bFalse,       sizeof(bFalse)       },
      {CKA_ID,           keyID,         sizeof(keyID) - 1    },
      {CKA_VERIFY,       &bTrue,        sizeof(bTrue)        },
      {CKA_KEY_TYPE,     &keyType,      sizeof(keyType)      },
      {CKA_MODULUS_BITS, &modulus_bits, sizeof(CK_ULONG)     }
    };

    CK_ATTRIBUTE privateKeyTemplate[] = {
      {CKA_LABEL,     prv_label, sizeof(prv_label) - 1},
      {CKA_TOKEN,     &bFalse,   sizeof(bFalse)       },
      {CKA_ID,        keyID,     sizeof(keyID) - 1    },
      {CKA_SIGN,      &bTrue,    sizeof(bTrue)        },
      {CKA_KEY_TYPE,  &keyType,  sizeof(keyType)      },
      {CKA_PRIVATE,   &bTrue,    sizeof(bTrue)        },
      {CKA_SENSITIVE, &bTrue,    sizeof(bTrue)        }
    };

    CK_MECHANISM mech = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0};

    CK_RV result = C_GenerateKeyPair(hSession,
                                     &mech,
                                     publicKeyTemplate,
                                     sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                     privateKeyTemplate,
                                     sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE),
                                     &pubKey,
                                     &prvKey);
    if (result != CKR_OK) {
        throw std::runtime_error("C_GenerateKeyPair returned an error: " + std::to_string(result));
    }

    std::cout << "An RSA key pair got generated!" << std::endl;
    return prvKey;
}

void sign(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPrivateKey)
{
    CK_RV        result;
    CK_MECHANISM mechanism;
    CK_BYTE      signature[256];
    CK_ULONG     ulSignatureLen = sizeof(signature);
    CK_BYTE      data[]         = "This data will get signed.";

    mechanism.mechanism      = CKM_SHA256_RSA_PKCS;
    mechanism.pParameter     = NULL;
    mechanism.ulParameterLen = 0;

    result = C_SignInit(hSession, &mechanism, hPrivateKey);
    if (result != CKR_OK) {
        throw std::runtime_error("C_SignInit returned an error: " + std::to_string(result));
    }

    result = C_Sign(hSession, data, sizeof(data), signature, &ulSignatureLen);
    if (result != CKR_OK) {
        throw std::runtime_error("C_Sign returned an error: " + std::to_string(result));
    }

    std::cout << "Some data got signed!" << std::endl;
}
