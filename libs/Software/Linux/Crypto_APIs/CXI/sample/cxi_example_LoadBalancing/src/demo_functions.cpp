/**
 *  \file    demo_functions.cpp
 *  \brief   This file contains an assortment of global functions, of which receivingRequests() is the most important.
 *  
 *  \author  Utimaco GmbH
 *  \date    25.01.2017
 *  \version 1.0.3
 *  
 *  \details The function receivingRequests() is started in a thread from within the main() routine. 
 *           It creates a fixed number (given in `lb.cfg`) of signing requests. With some time delay 
 *           (type and mean of delay time distribution are given in `lb.cfg`) the newly created thread 
 *           enters the request-container, where all requests are queued for processing from within main().
 *  
 *           All remaining functions are utility functions of minor importance.  
 */

#include "demo.h"


/**
 *  \brief      simulation of incoming signing requests
 *  
 *  \param [in] input structure of type HandoverStruct
 *  
 *  \return     exit status (zero = o.k.)  
 *  
 *  \details    Paramaters of the `lb.cfg` configuration file are handed over via the HandoverStruct input.
 *              This includes different transaction  bundle sizes / repeats (via fctInput->factor[] and 
 *              fctInput->nr_repeats), the overall number of transactions to create, as well as  type and
 *              mean of the distribution of time delays between consecutive incoming requests. 
 *              Created requests are stored in the openRequests container, which is as well accessed from within
 *              the main() routine.
 */
#ifdef OSYS_win
int receivingRequests(void* input)
{
#else
void* receivingRequests(void* input)
{
    int* returnValue = (int*)malloc(sizeof(int));
#endif
    int                  err          = 0;
    HandoverStruct*      fctInput     = (HandoverStruct*)input;
    std::queue<Request>* openRequests = fctInput->requests;

    struct timeb timestamp;
#ifndef OSYS_win
    struct timespec structInterval;
#endif
    unsigned int msInterval = 0;

    PropertyList keyTemplate;
    ByteArray    signature;
    FILE*        fp_out_received = NULL;

    ByteArray data(
      "All CryptoServer in a cluster must be configured identically. "
      "A new connection is always established to the CryptoServer with the least "
      "number of existing connections. In case of communication errors the API "
      "automatically switches to the next device and tries to execute the command on "
      "that CryptoServer. Only if the API wasn't able to execute the command on any device, "
      "it gives up and throws an exception.");

    // hash data
    Hash hash;
    hash.init(CXI_MECH_HASH_ALGO_SHA256);
    hash.update(data);
    hash.final();

    // specify which key to use: Group=sample Name="cxi LB key"
    keyTemplate.setGroup((char*)fctInput->group.c_str());
    keyTemplate.setName((char*)fctInput->keyName.c_str()); // assumes that RSA or ECDS key with this name exists

    // set seed for rand()
    ftime(&timestamp);
    srand((unsigned long)timestamp.time);

    // open output file saving number of received requests
    if ((fp_out_received = fopen("data_requests_in.txt", "w")) == (FILE*)NULL) {
        printf("\n[openOutputFiles] write on data_requests_in.txt failed: %s\n", strerror(errno));
        CLEANUP(errno);
    }
    fprintf(fp_out_received, "# Time[s]\t NrOfReceivedRequests\n");

    // simulate incoming requests
    for (int n = 0; n < fctInput->nr_requests; n++) {
        // simulate delay
        if (fctInput->distribution_type.compare("exponential") == 0) {
            msInterval = (unsigned int)((-1.0) * (fctInput->distribution_mean)
                                        * log(1.0 - (double)rand() / (double)RAND_MAX));
        }
        if (fctInput->distribution_type.compare("uniform") == 0) {
            msInterval = fctInput->distribution_mean;
        }
#ifdef OSYS_win
        Sleep((DWORD)msInterval);
#else
        structInterval.tv_sec  = (int)((double)msInterval / 1000.0);
        structInterval.tv_nsec = ((long)msInterval - (long)(structInterval.tv_sec * 1000)) * 1000000;
        nanosleep(&structInterval, (struct timespec*)NULL);
#endif

        // create request and put into FIFO container "openRequests"
        int     index = (int)((double)rand() / (double)RAND_MAX * ((double)fctInput->N));
        Request request(n + 1, 's', keyTemplate, hash, fctInput->factor[index] * fctInput->nr_repeats);

#ifdef OSYS_win
        EnterCriticalSection(fctInput->pCriticalSection);
#else
        pthread_mutex_lock(fctInput->pMutex);
#endif
        openRequests->push(request);
#ifdef OSYS_win
        LeaveCriticalSection(fctInput->pCriticalSection);
#else
        pthread_mutex_unlock(fctInput->pMutex);
#endif

        if (openRequests->size() >= fctInput->maxContainerSize) {
            printf("\n\n --> maximum request container size of %d reached.\n\n", fctInput->maxContainerSize);
            CLEANUP(ERR_MAX_CONTAINERSIZE);
        }

        // remember time of request receiving
        ftime(&timestamp);
        fprintf(fp_out_received,
                "%lf\t%d\n",
                (double)((unsigned long)(timestamp.time * 1000 + timestamp.millitm) - fctInput->starttime) / 1000.0,
                n + 1);
    }
    printf("%.2lf s\t --> all requests received.\n",
           (double)((unsigned long)(timestamp.time * 1000 + timestamp.millitm) - fctInput->starttime) / 1000.0);

cleanup:
    fctInput->bReceptionFinished = true;
    if (fp_out_received != NULL) {
        fclose(fp_out_received);
    }
#ifdef OSYS_win
    return err;
#else
    (*returnValue) = err;
    return returnValue;
#endif
}

/**
 *  \brief      remove leading and trailing white spaces and tabs from a std::string 
 *  
 *  \param [in] s string variable to be trimmed
 *  
 *  \return     void
 *     
 */
void removeSurroundingWhitespaces(string& s)
{
    size_t pos;
#ifdef OSYS_win
    pos = s.find_first_not_of(" \t");
    s.erase(0, pos);
    pos = s.find_last_not_of(" \t");
#else
    pos = s.find_first_not_of(" \t\r");
    s.erase(0, pos);
    pos = s.find_last_not_of(" \t\r");
#endif
    if (s.npos != pos) {
        s.erase(pos + 1);
    }
}

/**
 *  \brief      parser of the example's configuration file `lb.cfg`
 *  
 *  \param [in] cfgfile name and path of the file to get parsed
 *  \param [in] cxifile returns name and path to the cxi configuration file as specified in cfgfile 
 *  \param [in] input writes and returns here several parameters from the cfgfile 
 *  \param [in] user returns cryptographic user name as specified in cfgfile
 *  \param [in] pwd returns cryptographic user password as specified in cfgfile
 *  \param [in] method returns method as specified in cfgfile
 *  
 *  \return     exit status (zero = o.k.) 
 *  
 *  \details    Reads the parameters as specified in cfgfile into variables
 */
int parseConfigFile(char* cfgfile, string& cxifile, HandoverStruct* input, string& user, string& pwd, string& method)
{
    ifstream fs_in;
    string   line, key, value;

    fs_in.open(cfgfile);
    while (getline(fs_in, line)) {
        if (line.length() <= 0) {
            continue;
        }
        if (line[0] == '#') {
            continue;
        }

        istringstream iss_line(line);
        if (getline(iss_line, key, '=')) {
            removeSurroundingWhitespaces(key);
            if (key.compare("CxiConfigFile") == 0) {
                getline(iss_line, cxifile);
                removeSurroundingWhitespaces(cxifile);
                continue;
            }
            if (key.compare("CryptoUser") == 0) {
                getline(iss_line, user);
                removeSurroundingWhitespaces(user);
                continue;
            }
            if (key.compare("UserPassword") == 0) {
                getline(iss_line, pwd);
                removeSurroundingWhitespaces(pwd);
                continue;
            }
            if (key.compare("UserGroup") == 0) {
                getline(iss_line, input->group);
                removeSurroundingWhitespaces(input->group);
                continue;
            }
            if (key.compare("KeyName") == 0) {
                getline(iss_line, input->keyName);
                removeSurroundingWhitespaces(input->keyName);
                continue;
            }
            if (key.compare("NrOfRequests") == 0) {
                getline(iss_line, value);
                removeSurroundingWhitespaces(value);
                if (atoi(value.c_str()) > 0) {
                    input->nr_requests = atoi(value.c_str());
                } else {
                    printf("[parseConfigFile] Invalid Requests value (positive integer required) in config file %s\n",
                           cfgfile);
                    fs_in.close();
                    return ERR_INPUT;
                }
                continue;
            }
            if (key.compare("WaitingTimeDistribution") == 0) {
                getline(iss_line, input->distribution_type);
                removeSurroundingWhitespaces(input->distribution_type);
                if (input->distribution_type.compare("uniform") && input->distribution_type.compare("exponential")) {
                    printf(
                      "[parseConfigFile] Invalid distribution type (only: uniform or exponential) in config file %s\n",
                      cfgfile);
                    fs_in.close();
                    return ERR_INPUT;
                }
                continue;
            }
            if (key.compare("WaitingTimeMean") == 0) {
                getline(iss_line, value);
                removeSurroundingWhitespaces(value);
                if (atoi(value.c_str()) > 0) {
                    input->distribution_mean = (int)atoi(value.c_str());
                } else {
                    printf(
                      "[parseConfigFile] Invalid dsitribution mean value (positive integer required) in config file "
                      "%s\n",
                      cfgfile);
                    fs_in.close();
                    return ERR_INPUT;
                }
                continue;
            }
            if (key.compare("TransactionRepeats") == 0) {
                getline(iss_line, value);
                removeSurroundingWhitespaces(value);
                if (atoi(value.c_str()) > 0) {
                    input->nr_repeats = atoi(value.c_str());
                } else {
                    printf(
                      "[parseConfigFile] Invalid transaction repeat value (positive integer required) in config file "
                      "%s\n",
                      cfgfile);
                    fs_in.close();
                    return ERR_INPUT;
                }
                continue;
            }
            if (key.compare("RepeatFactors") == 0) {
                getline(iss_line, value);
                removeSurroundingWhitespaces(value);
                input->N      = count(value.begin(), value.end(), ',') + 1;
                input->factor = new int[input->N];
                istringstream iss_value(value);
                for (unsigned int i = 0; i < input->N - 1; i++) {
                    getline(iss_value, value, ',');
                    removeSurroundingWhitespaces(value);
                    if (atoi(value.c_str()) > 0) {
                        input->factor[i] = atoi(value.c_str());
                    } else {
                        printf(
                          "[parseConfigFile] Invalid repeat factor (positive integer required) in config file %s\n",
                          cfgfile);
                        fs_in.close();
                        return ERR_INPUT;
                    }
                }
                getline(iss_line, value);
                removeSurroundingWhitespaces(value);
                if (atoi(value.c_str()) > 0) {
                    input->factor[input->N - 1] = atoi(value.c_str());
                } else {
                    printf("[parseConfigFile] Invalid repeat factor (positive integer required) in config file %s\n",
                           cfgfile);
                    fs_in.close();
                    return ERR_INPUT;
                }
                continue;
            }
            if (key.compare("MaximumContainerSize") == 0) {
                getline(iss_line, value);
                removeSurroundingWhitespaces(value);
                if (atoi(value.c_str()) > 0) {
                    input->maxContainerSize = atoi(value.c_str());
                } else {
                    printf(
                      "[parseConfigFile] Invalid maximum container size (positive integer required) in config file "
                      "%s\n",
                      cfgfile);
                    fs_in.close();
                    return ERR_INPUT;
                }
                continue;
            }
        }
    }
    fs_in.close();

    return 0;
}
