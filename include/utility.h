#ifndef UTILITY_H
#define UTILITY_H

#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
extern char* optarg;
extern int optind;
extern int optopt;
extern int opterr;
extern int optreset;

void 
parse_args(int argc, 
           char* const argv[],
           char* const source_addr,
           int* const source_port,
           char* const dest_addr,
           int* const dest_port);

uint16_t 
internet_checksum(uint16_t* buf, int nbytes);

uint16_t
tcp_checksum(struct ip* ip_hdr, struct tcphdr* tcphdr);

#endif /* UTILITY_H */
