#ifndef UTILITY_H
#define UTILITY_H

#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define kPKT_TYPE_OOB    0
#define kPKT_TYPE_SYN    1
#define kPKT_TYPE_SYNACK 2
#define kPKT_TYPE_ACK    3

extern char* optarg;
extern int optind;
extern int optopt;
extern int opterr;
extern int optreset;

void
prepare_tcp_pkt(const int pkt_type,
                char** pkt_p, 
                const int src_port,
                const int dst_port,
                char* src_addr,
                char* dst_addr);

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

void
hexdump(const char* const desc, const void* const addr, int len);


#endif /* UTILITY_H */
