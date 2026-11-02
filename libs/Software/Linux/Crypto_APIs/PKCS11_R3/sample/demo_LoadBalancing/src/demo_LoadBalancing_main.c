/**
 *  \file    demo_LoadBalancing_main.c
 *  \brief   This file contains the main() routine.
 *  
 *  \author  Utimaco GmbH
 *  \date    18.04.2016
 *  \version 1.0.2
 *  
 *  \details The example performs RSA 2084 bit transactions:         
 *           1. key pair generation, 
 *           2. signing 
 *           3. verifying. 
 *           
 *           On the command-line, you enter the number of key
 *           pair generations, the number of signing operations and the number of
 *           verifying operations. The program outputs the time needed to perform
 *           the chosen set of transactions. You can run the example on different
 *           HSM cluster sizes and see how computation time scales with cluster size.
 *           This is linear in the case of real HSM devices. Remember that 
 *           results with HSM simulators are dependent on the power and load of the host the
 *           simulators are running on.
 *  
 *           Example usage:
 *  
 *                demo_LoadBalancing.exe -LIB %CS_PAT%\Lib\cs_pkcs11_R3.dll  -keyGen 2 -sign 10 -verify 20  
 *           
 */

#include "demo_LoadBalancing.h"

/**
 *  Expected command-line arguments:
 *  
 *         -LIB     [char*]             path to PKCS#11 dynamic library file 
 *         -keyGen  [positive integer]  number of RSA 2084 bit key pair generation transactions 
 *         -sign    [positive integer]  number of sign transactions 
 *         -verify  [positive integer]  number of verify transactions 
 *  
 *  \return  exit status (zero = o.k.)
 *  
 *  \details The main routine first checks for valid command-line input, then bundles the input parmeters 
 *           in the structure ParamLB and hands them over to the  load_balancing_demo() function. In case 
 *           of success, the program informs about the performed transactions and the time needed to 
 *           complete it.
 *  
 */
int main(int argc, char* argv[])
{
    int      err = 0;
    int      i   = 0;
    ParamLB* input;
    char*    pointer;

    input = newParamLB();

    // read command line arguments
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-LIB") == 0 && i + 1 < argc) {
            if (strlen(argv[i + 1]) != 0 && strcmp(argv[i + 1], "-keyGen") != 0 && strcmp(argv[i + 1], "-sign") != 0
                && strcmp(argv[i + 1], "-verify") != 0) {
                input->libPath = (char*)malloc(sizeof(char) * (strlen(argv[i + 1]) + 1));
                strcpy(input->libPath, argv[i + 1]);
            } else {
#ifdef OSYS_win
                printf("\nEnter valid path: -LIB <library path>\\cs_pkcs11_R3.dll\n\n");
#else
                printf("\nEnter valid path: -LIB <libary path>/cs_pkcs11_R3.so\n\n");
#endif
                goto end;
            }
        }
        if (strcmp(argv[i], "-keyGen") == 0 && i + 1 < argc) {
            input->nK = (int)strtol(argv[i + 1], &pointer, 10);
            if (pointer == argv[i + 1] || *pointer != '\0') {
                printf("Please enter a positive Integer behind '-keyGen'.\n");
                goto end;
            }
        }
        if (strcmp(argv[i], "-sign") == 0 && i + 1 < argc) {
            input->nS = (int)strtol(argv[i + 1], &pointer, 10);
            if (pointer == argv[i + 1] || *pointer != '\0') {
                printf("Please enter a positive Integer behind '-sign'.\n");
                goto end;
            }
        }
        if (strcmp(argv[i], "-verify") == 0 && i + 1 < argc) {
            input->nV = (int)strtol(argv[i + 1], &pointer, 10);
            if (pointer == argv[i + 1] || *pointer != '\0') {
                printf("Please enter a positive Integer behind '-verify'.\n");
                goto end;
            }
        }
    }

    // check for valid input
    if (input->nK < 0 || input->nS < 0 || input->nV < 0 || input->nK + input->nS + input->nV == 0
        || input->libPath == NULL) {
        printf("\nSYNTAX:\n\n");
#ifdef OSYS_win
        printf("%s -LIB <library path>\\cs_pkcs11_R3.dll ", argv[0]);
#else
        printf("%s -LIB -LIB <libary path>/cs_pkcs11_R3.so ", argv[0]);
#endif
        printf("-keyGen <NonNegInt> -sign <NonNegInt> -verify <NonNegInt> \n");
        printf("\nAt least one of the operations\n");
        printf("\t- RSA 2084 bit key pair generation\n");
        printf("\t- signing\n");
        printf("\t- or verification\n");
        printf("has to be performed once.\n");
        err = 1;
        goto end;
    }


    // run demo
    err = load_balancing_demo(input);

    if (err != 0) {
        printf("Terminated with error %d.\n", err);
    } else {
        printf("\ncreated  %d RSA 2048 bit key pair/s \n", input->nK);
        printf("signed   %d times/s \n", input->nS);
        printf("verified %d time/s \n", input->nV);
        printf("\n total time         : %li ms\n", input->duration);
    }


end:
    if (input != NULL) {
        if (input->libPath != NULL) {
            free(input->libPath);
        }
        free(input);
    }
    return err;
}
