/**
 * constant.c
 * values of the constants defined in include/constant.h
 */
#include <stddef.h>
#include "constant.h"


/* Protocol header related */
const size_t kIP_HDR_LEN  = 20;
const size_t kTCP_HDR_LEN = 20;
const size_t kUDP_HDR_LEN = 8;
const size_t kIPADDR_MAXLEN = 16;

/* Program behavior related */
const size_t kPKT_MAX_LEN         = 256;
const size_t kTRAILER_OFFSET      = 4;
const size_t kOPTIONS_LENGTH      = 12;

const int    kBUFFER_MAX_LEN      = 1024;
const int    kSRC_PORT_DEFAULT    = 64000;
const int    kDST_PORT_DEFAULT    = 64001;
const int    kLISTEN_PORT_DEFAULT = 64001;

const char*  kIP_LOCALHOST        = "127.0.0.1";
const char*  kPAYLOAD             = "Hello ";

int          verbose              = 0; /* not verbose by default */

