#ifndef CONSTANT_H_
#define CONSTANT_H_

#include <stddef.h>

/* Protocol header related */
extern const size_t kIP_HDR_LEN;
extern const size_t kTCP_HDR_LEN;
extern const size_t kUDP_HDR_LEN;

/* Program behavior related */
extern const size_t kPKT_MAX_LEN;
extern const size_t kTRAILER_OFFSET;
extern const size_t kOPTIONS_LENGTH;

extern const int    kBUFFER_MAX_LEN;
extern const int    kSRC_PORT_DEFAULT;
extern const int    kDST_PORT_DEFAULT;
extern const int    kLISTEN_PORT_DEFAULT;

extern const char*  kIP_LOCALHOST;
extern const char*  kPAYLOAD;

#endif
