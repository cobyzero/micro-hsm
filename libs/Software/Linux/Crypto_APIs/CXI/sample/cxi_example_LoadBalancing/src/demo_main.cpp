/**
 *  \file    demo_main.cpp
 *  \brief   This file contains the main() routine.
 *  
 *  \author  Utimaco GmbH
 *  \date    07.05.2018
 *  \version 1.0.5
 *  
 *  \details The example can simulate different load balancing scenarios. It         
 *           1. shows how to employ Utimaco's load balancing feature using the CXI interface.
 *           2. offers you a set of parameters to vary and simulate your needs.
 *           3. can provide you with estimates and ideas how to best integrate Utimaco's HSMs in your infrastructure.
 *           4. DOESN'T provide you with THE ultimate and best solution for your infrastructure depending specific requirements. 
 *
 *           The example can sign and verify hashed data. For sake of simplicity a fixed piece of data is being used.
 *           The default configuration only uses the sign operation. It can be repeated as to represent transaction
 *           bundles. In this way a more complex and/or longer lasting request can be simulated. 
 *                      
 *           The example's configuration is done in the file `lb.cfg` located in the folder `etc`.
 *           Configuration items are:
 *               - location of the CXI configuration file `cxi.cfg` (necessary configuration in `cxi.cfg`: device addresses)
 *               - user name, password, user group, key name to be used for signing
 *               - Incoming request frequency (exponential or uniform wating time distribution between consecutive requests)
 *               - different transaction repeats (simulating different type of requests or request bundles)
 *               - and more ...
 *  
 *           Example usage:
 *  
 *                cxi_demo_LoadBalancing.exe cfg=..\..\etc\lb.cfg  
 *           
 */

#include "demo.h"


/**
 *  Command-line arguments:
 *  
 *         cfg=[char*]        path to example's configuration file `lb.cfg`, default is `lb.cfg` 
 *  
 *  \return  exit status (zero = o.k.)
 *  
 *  \details Flowchart of the main routine: 
 *           1. check for valid command-line input
 *           2. parse the example's configuration file `lb.cfg`
 *           3. load and parse the cxi configuration file (whose location is given in `lb.cfg`)
 *           4. the total number of sessions is known now and arrays can be initialized
 *           5. the available session container is filled
 *           6. output files are prepared for receiveing the results
 *           7. request-receiving-thread is started, stopwatch is running from now on 
 *           8. enter while loop under the following condition: requests still need to be done or are still being executed
 *           9. inside the loop: a) if a session is available and a request is waiting then start a new request execution thread,
 *                               b) scan the status of all request execution threads. If request is finished, do 
 *                                  something with the finished thread and return session ID to available-session-container
 *          10. cleanup section: finish threads, free memory, close files 
 *              
 *  
 */
int main(int argc, char** argv)
{
    int   err     = 0;
    char* cfgfile = NULL;

    FILE* fp_out_finished = NULL;
    FILE* fp_out_queuing  = NULL;

    int  maxSessions          = 0;
    int  countSuccess         = 0;
    int  countErrFinishThread = 0;
    int  countExitError       = 0;
    bool stillOneActive       = false;
    int  exitCode             = 0;
    int  threadStatus         = 0;

#ifdef OSYS_win
    DWORD  idReceptionThread      = 0;
    HANDLE pReceptionThreadHandle = NULL;
#else
    pthread_t idReceptionThread;
    int*      pReceptionReturn = NULL;
#endif

    string cxifile;
    string user;
    string pwd;
    string method;
    Config config;

    Execute** thread  = NULL;
    Cxi**     cxi     = NULL;
    Request** request = NULL;

    std::queue<int>      openSessions;
    std::queue<Request>* openRequests = NULL;

    Log& log = Log::getInstance();

    struct timeb timestamp;
#ifdef OSYS_win
    CRITICAL_SECTION CriticalSection;
#else
    pthread_mutex_t pthread_mutex;
#endif

    HandoverStruct handover = {NULL, "", "", "", 0, 0, 0, NULL, 0, false, NULL, 0, 0};


    // initialize critical section
#ifdef OSYS_win
    if (!InitializeCriticalSectionAndSpinCount(&CriticalSection, 0x00000400)) {
        ENDUP(ERR_CRITICAL_SECTION);
    }
    handover.pCriticalSection = &CriticalSection;
#else
    if (pthread_mutex_init(&pthread_mutex, NULL) != 0) {
        ENDUP(ERR_CRITICAL_SECTION);
    }
    handover.pMutex = &pthread_mutex;
#endif

    // screen command-line input for config file
    for (int i = 1; i < argc; i++) {
        if (strncasecmp(argv[i], (char*)"cfg=", 4) == 0) {
            cfgfile = argv[i] + 4;
        } else {
            printf("[main] Invalid argument: %s\n", argv[i]);
            ENDUP(ERR_INPUT);
        }
    }
#ifdef OSYS_win
    if (cfgfile == NULL) {
        cfgfile = (char*)"..\\..\\etc\\lb.cfg";
    }
#else
    if (cfgfile == NULL) {
        cfgfile = (char*)"../../etc/lb.cfg";
    }
#endif

    // parse sample config file
    err = parseConfigFile(cfgfile, cxifile, &handover, user, pwd, method);
    if (err != 0) {
        ENDUP(err);
    }

    // load config file
    try {
        config = Config((char*)cxifile.c_str());
    } catch (const Exception& ex) {
        printf("[main] %sat %s [%d]\n", ex.err_str, ex.where, ex.line);
        ENDUP(ex.err);
    }
    log.init(config);

    // read number of devices from config file
    printf("\nCryptoServer(s): %s\n\n", config.getString("Device", "").c_str());
    maxSessions = SESSIONS_PER_HSM * (int)config.getStringValues("Device").size();
    maxSessions = (maxSessions < handover.nr_requests) ? maxSessions : handover.nr_requests;
    printf("Total number of connections available: %d\n\n", maxSessions);
    printf("Time \t Request container size \t [success] \t [error]\n");
    printf("---- \t ---------------------- \t --------- \t -------\n\n");

    try {
        // allocate memory for arrays and container
        thread  = new Execute*[maxSessions];
        cxi     = new Cxi*[maxSessions];
        request = new Request*[maxSessions];

        openRequests = new std::queue<Request>;

        //  initialize arrays
        for (int i = 0; i < maxSessions; i++) {
            thread[i]  = NULL;
            request[i] = NULL;
            cxi[i]     = NULL;
        }

        // fill arrays and open Secure Messaging connections
        for (int i = 0; i < maxSessions; i++) {
            thread[i]  = new Execute();
            request[i] = new Request();
            cxi[i]     = new Cxi(config);
            cxi[i]->logon_pass((char*)user.c_str(), (char*)pwd.c_str(), true);

            openSessions.push(i);
        }
    } catch (const Exception& ex) {
        printf("[main] %sat %s [%d]\n", ex.err_str, ex.where, ex.line);
        CLEANUP(ex.err);
    }


    // open output file saving number of finished requests
    if ((fp_out_finished = fopen("data_requests_out.txt", "w")) == (FILE*)NULL) {
        printf("\n[openOutputFiles] write on data_requests_out.txt failed: %s\n", strerror(errno));
        CLEANUP(errno);
    }
    fprintf(fp_out_finished, "# Configuration Files: %s  %s\n", cfgfile, (char*)cxifile.c_str());
    fprintf(fp_out_finished, "# Time[s]\t NrOfFinishedRequests\n");

    // open output file saving queuing requests
    if ((fp_out_queuing = fopen("data_requests_queuing.txt", "w")) == (FILE*)NULL) {
        printf("\n[openOutputFiles] write on data_request_queuing.txt failed: %s\n", strerror(errno));
        CLEANUP(errno);
    }
    fprintf(fp_out_queuing, "# Configuration Files: %s  %s\n", cfgfile, (char*)cxifile.c_str());
    fprintf(fp_out_queuing, "# Time[s]\t NrOfQueuingRequests\n");


    // start the thread filling the request container
    handover.requests = openRequests;
    ftime(&timestamp);
    handover.starttime = (unsigned long)(timestamp.time * 1000 + timestamp.millitm);

#ifdef OSYS_win
    if ((pReceptionThreadHandle = CreateThread(
           NULL, 0, (LPTHREAD_START_ROUTINE)receivingRequests, (void*)&handover, 0, &idReceptionThread))
        == 0) {
        err = GetLastError();
        printf("[main] CreateThread ID=%d returned error: %d\n", idReceptionThread, err);
        CLEANUP(err);
    }
#else
    if ((err = pthread_create(&idReceptionThread, NULL, receivingRequests, (void*)&handover)) != 0) {
        printf("[main] CreateThread ID=%lu returned error: %d\n", idReceptionThread, err);
        CLEANUP(err);
    }
#endif

    // distribute requests on sessions
    try {
        // start and check threads as long as requests are present or receiving request thread is still active or threads are still running
        while (!openRequests->empty() || stillOneActive || handover.bReceptionFinished == false) {
            countErrFinishThread = 0;

            if (!openSessions.empty() && !openRequests->empty()) {
                // get first free session from session container
                int i = openSessions.front();

                // get first request from request container
                (*request[i]) = openRequests->front();

                // start processing request
                err = thread[i]->startThread(request[i], cxi[i]);
                if (err == 0) {
                    // remove session and from available-session-container
                    openSessions.pop();
                    // remove request from requests-to-do-container
#ifdef OSYS_win
                    EnterCriticalSection(&CriticalSection);
#else
                    pthread_mutex_lock(&pthread_mutex);
#endif
                    openRequests->pop();
#ifdef OSYS_win
                    LeaveCriticalSection(&CriticalSection);
#else
                    pthread_mutex_unlock(&pthread_mutex);
#endif

                    // save time and size of session container
                    ftime(&timestamp);
                    fprintf(fp_out_queuing,
                            "%lf\t%lu\n",
                            (double)((unsigned long)(timestamp.time * 1000 + timestamp.millitm) - handover.starttime)
                              / 1000.0,
                            (unsigned long)openRequests->size());
                }
            }

            // check the thread's exitCode: still running, finished, error
            stillOneActive = false;
            for (int i = 0; i < maxSessions; i++) {
                threadStatus = thread[i]->getThreadStatus();
                if (threadStatus == RUN_ACTIVE) {
                    stillOneActive = true;
                } else if (threadStatus != ERR_NO_THREAD) {
                    exitCode        = 0;
                    int returnValue = thread[i]->finishThread(&exitCode);
                    if (returnValue == 0) {
                        // no problem in thread, therefore return session to free session container
                        openSessions.push(i);

                        if (exitCode == 0) {
                            // do something with the finished requests -  here we only count them ..
                            countSuccess += 1;
                            if (countSuccess == 1 || countSuccess % 10 == 0
                                || request[i]->requestID == handover.nr_requests) {
                                ftime(&timestamp);
                                printf("%.2lf s\t\t %lu\t\t\t %d\t\t %d\n",
                                       (double)((unsigned long)(timestamp.time * 1000 + timestamp.millitm)
                                                - handover.starttime)
                                         / 1000.0,
                                       (unsigned long)openRequests->size(),
                                       countSuccess,
                                       countExitError);
                            }
                        } else {
                            // do something in case request execution returned error - here we only count them ..
                            countExitError += 1;
                        }

                        // save time and number of finished requests
                        ftime(&timestamp);
                        fprintf(
                          fp_out_finished,
                          "%lf\t%d\n",
                          (double)((unsigned long)(timestamp.time * 1000 + timestamp.millitm) - handover.starttime)
                            / 1000.0,
                          countExitError + countSuccess);

                    } else {
                        countErrFinishThread += 1; // count number of threads which did not finish properly
                                                   // session will be blocked and not reused again
                        ftime(&timestamp);
                        printf("%.2lf s\t --> active connections = %d\n",
                               (double)((unsigned long)(timestamp.time * 1000 + timestamp.millitm) - handover.starttime)
                                 / 1000.0,
                               maxSessions - countErrFinishThread);
                    }
                }
            }

            // if all threads (=all sessions) returned an error, exit the loop and finish program
            if (countErrFinishThread == maxSessions) {
                break;
            }
        }
    } catch (const Exception& ex) {
        printf("[main] %sat %s [%d]\n", ex.err_str, ex.where, ex.line);
        CLEANUP(ex.err);
    }

    printf("\n\n --> %d of %d requests finished successfully.\n", countSuccess, handover.nr_requests);
    printf(" --> %d of %d requests returned an error.\n", countExitError, handover.nr_requests);
    printf(" --> %d of %d threads returned an error.\n", countErrFinishThread, maxSessions);


    // program jumps here in case of exception error
cleanup:

    // call destructor of Cxi, Request and Execute Class
    for (int i = 0; i < maxSessions; i++) {
        if (thread != NULL) {
            delete thread[i];
        }
        if (request != NULL) {
            delete request[i];
        }
        if (cxi != NULL) {
            if (cxi[i] != NULL) {
                cxi[i]->logoff();
                delete cxi[i];
            }
        }
    }
    delete[] thread;
    delete[] request;
    delete[] cxi;

    // finish receiving request thread properly
#ifdef OSYS_win
    if (pReceptionThreadHandle != NULL) {
        err = WaitForSingleObject(pReceptionThreadHandle, INFINITE);
        if (err != 0) {
            printf("[main] WaitForSingleObject for thread ID %d returned: %d\n", idReceptionThread, err);
        }
        if (!GetExitCodeThread(pReceptionThreadHandle, (DWORD*)&exitCode)) {
            int iErr = GetLastError();
            printf("[main] GetExitCodeThread returned error for thread %d: %d\n", idReceptionThread, iErr);
            err = iErr ? iErr : err;
        }
        if (!CloseHandle(pReceptionThreadHandle)) {
            int iErr = GetLastError();
            printf("[main] CloseHandle returned error for thread %d: %d\n", idReceptionThread, iErr);
            err = iErr ? iErr : err;
        }
        err = exitCode ? exitCode : err;
    }
#else
    if ((err = pthread_join(idReceptionThread, (void**)&pReceptionReturn)) != 0) {
        printf("[main]: pthread_join returned error: %d\n", err);
    }
    err = (pReceptionReturn && *pReceptionReturn) ? (*pReceptionReturn) : err;
    free(pReceptionReturn);
#endif

    err = countExitError ? ERR_EXECUTE_REQUEST : err;
    err = countErrFinishThread ? ERR_FINISH_THREAD : err;

    // finish up
    if (fp_out_finished != NULL) {
        fclose(fp_out_finished);
    }
    if (fp_out_queuing != NULL) {
        fclose(fp_out_queuing);
    }

    if (handover.factor != NULL) {
        delete[] handover.factor;
    }
    if (openRequests != NULL) {
        delete openRequests;
    }

#ifdef OSYS_win
    DeleteCriticalSection(&CriticalSection);
#else
    pthread_mutex_destroy(&pthread_mutex);
#endif

end:

#ifdef OSYS_win
    cout << "\7\npress <ENTER>\n";
    while (cin.get() != 10)
        ;
#else
    cout << "\7\n\n";
#endif

    return err;
}
