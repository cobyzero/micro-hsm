/**
 *  \file  demo_MultiThreading.h
 *  \brief Header file to run demo_MultiThreading with exemplary cryptographic operations
 */

#include "cryptoki.h"

#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

// Generate an RSA key pair and return the private key handle as an exemplary cryptographic operation
CK_OBJECT_HANDLE generate_rsa_key_pair(CK_SESSION_HANDLE hSession);

// Sign some data using a private RSA key as an exemplary cryptographic operation
void sign(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hPublicKey);
