#ifndef SGX_LOG_H
#define SGX_LOG_H


#include <stdio.h>


#ifdef AARNO_SIMPLE
#include <sys/time.h>
#define sgx_printf printf
#else
int sgx_gettimeofday(struct timeval *tv, void *tz);
#define gettimeofday sgx_gettimeofday

void sgx_printf(const char *fmt, ...);
struct tm *sgx_localtime(const time_t *timep);
#define getlocaltime sgx_localtime
#endif




#ifndef TRACE_LOG
#define TRACE_LOG 0
#endif

#define LOG_TRACE(fmt, ...) \
  do { if (TRACE_LOG) { \
     timeval curTime; \
     gettimeofday(&curTime, NULL);            \
     int milli = curTime.tv_usec / 1000; \
     char buffer [sizeof "1212/12/12 12:12:12.999 [TRACE]"]; \
     strftime(buffer, sizeof(buffer), "%F %H:%M:%S", localtime(&curTime.tv_sec));\
     sgx_printf("%s.%03d [TRACE] %s:%d %s() [" fmt "]\n", buffer, milli, __FILE__, \
             __LINE__, __func__, ##__VA_ARGS__);} } while (0)


#ifndef DEBUG_LOG
#define DEBUG_LOG 0
#endif

#define LOG_DEBUG(fmt, ...) \
  do { if (DEBUG_LOG || TRACE_LOG) { \
     timeval curTime; \
     gettimeofday(&curTime, NULL);            \
     int milli = curTime.tv_usec / 1000; \
     char buffer [sizeof "1212/12/12 12:12:12.999 [DEBUG]"]; \
     strftime(buffer, sizeof(buffer), "%F %H:%M:%S", localtime(&curTime.tv_sec));\
     sgx_printf("%s.%03d [DEBUG] %s:%d %s() [" fmt "]\n", buffer, milli, __FILE__, \
             __LINE__, __func__, ##__VA_ARGS__);} } while (0)

#ifndef INFO_LOG
#define INFO_LOG 0
#endif

#define LOG_INFO(fmt, ...) \
  do { if (INFO_LOG || DEBUG_LOG || TRACE_LOG) { \
     timeval curTime; \
     gettimeofday(&curTime, NULL);            \
     int milli = curTime.tv_usec / 1000; \
     char buffer [sizeof "1212/12/12 12:12:12.999 [INFO] "]; \
     strftime(buffer, sizeof(buffer), "%F %H:%M:%S", localtime(&curTime.tv_sec));\
     sgx_printf("%s.%03d [INFO]  %s:%d %s() [" fmt "]\n", buffer, milli, __FILE__, \
             __LINE__, __func__, ##__VA_ARGS__);} } while (0)

#ifndef WARN_LOG
#define WARN_LOG 0
#endif

#define LOG_WARN(fmt, ...) \
  do { if (WARN_LOG || INFO_LOG || DEBUG_LOG || TRACE_LOG) { \
     timeval curTime; \
     gettimeofday(&curTime, NULL);            \
     int milli = curTime.tv_usec / 1000; \
     char buffer [sizeof "1212/12/12 12:12:12.999 [WARN] "]; \
     strftime(buffer, sizeof(buffer), "%F %H:%M:%S", localtime(&curTime.tv_sec));\
     sgx_printf("%s.%03d [WARN]  %s:%d %s() [" fmt "]\n", buffer, milli, __FILE__, \
             __LINE__, __func__, ##__VA_ARGS__);} } while (0)

#ifndef ERROR_LOG
#define ERROR_LOG 0
#endif

#define LOG_ERROR(fmt, ...) \
  do { if (ERROR_LOG || WARN_LOG || INFO_LOG || DEBUG_LOG || TRACE_LOG) { \
     timeval curTime; \
     gettimeofday(&curTime, NULL);            \
     int milli = curTime.tv_usec / 1000; \
     char buffer [sizeof "1212/12/12 12:12:12.999 [ERROR]"]; \
     strftime(buffer, sizeof(buffer), "%F %H:%M:%S", localtime(&curTime.tv_sec));\
     sgx_printf("%s.%03d [ERROR] %s:%d %s() [" fmt "]\n", buffer, milli, __FILE__, \
             __LINE__, __func__, ##__VA_ARGS__);} } while (0)

#endif  // SGX_LOG_H

