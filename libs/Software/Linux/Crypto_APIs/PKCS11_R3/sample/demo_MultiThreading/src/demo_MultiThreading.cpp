/**
 *  \file  demo_MultiThreading.cpp
 *  \brief main() routine for demo_MultiThreading
 *
 * To run this sample, install the SecurityServer and check the paths to the PKCS11_R3 header files and library in the
 * module cmakeFindPKCS11.cmake
 */
#include "demo_MultiThreading.h"

int main()
{
    // Parameters for main session with one slot for all thread sessions (for a shared authentication state)
    CK_RV             result;
    CK_SLOT_ID        slot        = 0;
    CK_SESSION_HANDLE mainSession = CK_INVALID_HANDLE;
    CK_BYTE           pin[]       = "12345678";

    // Parameters for thread creation with an exemplary number of four threads
    size_t                         thread_count = 4;
    std::vector<std::thread>       threads;
    std::vector<CK_SESSION_HANDLE> threadSessions;

    try {
        // Initialize the API with multithreading support. The flag CKF_OS_LOCKING_OK or ForceOSLocking in the config
        // file is required for multithreading
        CK_C_INITIALIZE_ARGS init_args;
        memset(&init_args, 0, sizeof(init_args));
        init_args.flags = CKF_OS_LOCKING_OK;
        result          = C_Initialize(&init_args);
        if (result != CKR_OK) {
            throw std::runtime_error("C_Initialize returned an error: " + std::to_string(result));
        }

        // Create the main session and log in
        result = C_OpenSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &mainSession);
        if (result != CKR_OK) {
            throw std::runtime_error("C_OpenSession returned an error: " + std::to_string(result));
        }
        result = C_Login(mainSession, CKU_USER, pin, sizeof(pin));
        if (result != CKR_OK) {
            throw std::runtime_error("C_Login returned an error: " + std::to_string(result));
        }

        // Generate an RSA key pair as an exemplary cryptographic operation
        CK_OBJECT_HANDLE private_key = generate_rsa_key_pair(mainSession);
        if (private_key == CK_INVALID_HANDLE) {
            throw std::runtime_error("The function generate_rsa_key_pair returned an invalid key handle.");
        }

        // Create sessions for each thread
        for (size_t i = 0; i < thread_count; i++) {
            // Open the session for each thread. No login is required due to the shared authentication state from
            // using the same slot
            CK_SESSION_HANDLE threadSession = CK_INVALID_HANDLE;
            result = C_OpenSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &threadSession);
            if (result != CKR_OK) {
                throw std::runtime_error("C_OpenSession returned " + std::to_string(result));
            }
            threadSessions.push_back(threadSession);
        }

        // Create threads and perform an exemplary cryptographic operation of signing data
        for (size_t i = 0; i < thread_count; i++) {
            // Let each thread sign data upon their creation, using the generated RSA key
            threads.push_back(std::thread(sign, threadSessions[i], private_key));
            std::cout << "Started thread " << i + 1 << std::endl;
        }

        // Wait for all threads
        for (auto& thread : threads) {
            thread.join();
        }
    } catch (std::runtime_error& e) {
        std::cout << e.what() << std::endl;
    }

    // Close the sessions and logout
    for (auto threadSession : threadSessions) {
        C_CloseSession(threadSession);
    }
    C_Logout(mainSession);
    C_CloseSession(mainSession);
    C_Finalize(NULL);

    return result;
}
