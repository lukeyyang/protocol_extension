/**
 * debug.h
 * macro magic for debugging/logging
 */
#ifndef DEBUG_H_
#define DEBUG_H_

#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "utility.h"
#include "constant.h"

#define clear_errno() \
        (errno == 0 ? "None" : strerror(errno))

#define LOGX(M, ...) \
        fprintf(stderr, "[ERROR] (%s:%d: errno: %s) " M "\n",\
                __FILE__, __LINE__, clear_errno(), ##__VA_ARGS__)

#define LOGW(M, ...) \
        fprintf(stderr, "[WARN] (%s:%d: errno: %s) " M "\n",\
                __FILE__, __LINE__, clear_errno(), ##__VA_ARGS__)

#define LOGV(M, ...) if (verbose) \
        fprintf(stderr, "[INFO] (%s:%d) " M "\n", \
                __FILE__, __LINE__, ##__VA_ARGS__)

#define LOGP(X, Y, Z) if (verbose) \
        hexdump(X, Y, Z)

#endif

