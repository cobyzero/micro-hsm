#ifndef _CS_MUTEX_H_
#define _CS_MUTEX_H_

#ifdef OSYS_win

#include <windows.h>

typedef struct {
    volatile LONG    init_ctr;
    volatile int     initialized;
    CRITICAL_SECTION cs;
} CS_MUTEX_TYPE;


#define CS_MUTEX_DECLARE(x)      CS_MUTEX_TYPE x
#define CS_MUTEX_DECLARE_INIT(x) CS_MUTEX_TYPE x = {0}
#define CS_MUTEX_INIT(x)         (x).initialized = (x).init_ctr = 0

#define INIT_MUTEX_ONCE(x)                                  \
    {                                                       \
        if (!(x).initialized) {                             \
            if (1 == InterlockedIncrement(&(x.init_ctr))) { \
                InitializeCriticalSection(&(x.cs));         \
                (x).initialized = 1;                        \
            } else                                          \
                while (!(x).initialized)                    \
                    Sleep(0);                               \
        }                                                   \
    }
#define CS_MUTEX_LOCK(x)               \
    {                                  \
        INIT_MUTEX_ONCE(x)             \
        EnterCriticalSection(&(x.cs)); \
    }

#define CS_MUTEX_UNLOCK(x)             \
    {                                  \
        INIT_MUTEX_ONCE(x)             \
        LeaveCriticalSection(&(x.cs)); \
    }

#define CS_MUTEX_DESTROY(x)             \
    {                                   \
        INIT_MUTEX_ONCE(x)              \
        DeleteCriticalSection(&(x.cs)); \
    }

#else // linux

#include <pthread.h>

#define CS_MUTEX_DECLARE(x)      pthread_mutex_t x
#define CS_MUTEX_DECLARE_INIT(x) pthread_mutex_t x = PTHREAD_MUTEX_INITIALIZER
#define CS_MUTEX_INIT(x)         pthread_mutex_init(&(x), NULL)

#define CS_MUTEX_LOCK(x)    pthread_mutex_lock(&(x))
#define CS_MUTEX_UNLOCK(x)  pthread_mutex_unlock(&(x))
#define CS_MUTEX_DESTROY(x) pthread_mutex_destroy(&(x))

#ifdef OSYS_macOS
// need this for pid_t
#include <sys/types.h>
#endif // OSYS_macOS

#endif // OSYS_win

#ifdef __cplusplus

class CS_Mutex
{
public:
    CS_Mutex(const int _use_locking = 1) : use_locking(_use_locking)
    {
        CS_MUTEX_INIT(mutex_impl);
    };
    ~CS_Mutex()
    {
        CS_MUTEX_DESTROY(mutex_impl);
    };

    void lock(void)
    {
        if (use_locking) {
            CS_MUTEX_LOCK(mutex_impl);
        }
    };
    void unlock(void)
    {
        if (use_locking) {
            CS_MUTEX_UNLOCK(mutex_impl);
        }
    };

private:
    //declarations only - no need to copy or assign a mutex object
    CS_Mutex(const CS_Mutex&);
    CS_Mutex& operator=(const CS_Mutex&);

    //controls Mutex behaviour
    const int use_locking;

    // The platform specific mutex implementation (see above)
    CS_MUTEX_DECLARE(mutex_impl);
};


class CS_Lock
{
public:
    CS_Lock(CS_Mutex& mutex) : m_mutex(mutex)
    {
        m_mutex.lock();
    };
    ~CS_Lock()
    {
        m_mutex.unlock();
    };

private:
    //declarations only - no need to copy or assign a lock object
    CS_Lock(const CS_Lock&);
    CS_Lock& operator=(const CS_Lock&);

    CS_Mutex& m_mutex;
};

#endif //__cplusplus


#endif //_CS_MUTEX_H_
