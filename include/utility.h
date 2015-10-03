#ifndef UTILITY_H
#define UTILITY_H

#include <unistd.h>
extern char* optarg;
extern int optind;
extern int optopt;
extern int opterr;
extern int optreset;

void 
parse_args(int argc, 
           char* const argv[],
           const char* source_addr,
           int* const source_port,
           const char* dest_addr,
           int* const dest_port);

uint16_t 
udp_checksum(uint16_t* buffer, int nwords);


#endif /* UTILITY_H */
