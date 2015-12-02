/**
 * constant.h
 * various constant definitions used in the project
 */

#ifndef CONSTANT_H_
#define CONSTANT_H_

#include <stddef.h>

#define kUSAGE "usage: %s [-h source_addr]"\
                         "[-f source_port]"\
                         "[-d dest_addr]"\
                         "[-p dest_port]"\
                         "[-v]"
#define kUSAGE_SIMPLE "usage: %s [-p port_number_to_listen_to] [-v]"

/* Protocol header related */
extern const size_t kIP_HDR_LEN;
extern const size_t kTCP_HDR_LEN;
extern const size_t kUDP_HDR_LEN;
extern const size_t kIPADDR_MAXLEN;

/* Program behavior related */
extern const size_t kPKT_MAX_LEN;
extern const size_t kTRAILER_OFFSET;
extern const size_t kOPTIONS_LENGTH;

extern const int    kBUFFER_MAX_LEN;
extern const int    kSRC_PORT_DEFAULT;
extern const int    kDST_PORT_DEFAULT;
extern const int    kLISTEN_PORT_DEFAULT;

extern const long   kSELECT_TIMEOUT;

extern const char*  kIP_LOCALHOST;
extern const char*  kPAYLOAD;

extern int          verbose;

#endif  /* CONSTANT_H_ */
