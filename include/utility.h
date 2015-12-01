/**
 * utility.h
 * useful (or not very much) functions used in the project
 */

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

/**
 * prepares a TCP packet with customization
 * supports creation of OOB, SYN, SYNACK, and ACK
 * creates OOB packets with one digit of random number attached at the end
 */
void
prepare_tcp_pkt(const int pkt_type,
                char** pkt_p, 
                const int src_port,
                const int dst_port,
                char* src_addr,
                char* dst_addr);

/**
 * parses command line arguments with four arguments, see usage
 */
void 
parse_args(int argc, 
           char* const argv[],
           char* const source_addr,
           int* const source_port,
           char* const dest_addr,
           int* const dest_port);

/**
 * parses command line arguments with one argument (port), used in server 
 */
void 
parse_args_simple(int argc, 
                  char* const argv[],
                  int* const local_port);

/**
 * Internet checksum per RFC 1071 -- not really used
 */ 
uint16_t 
internet_checksum(uint16_t* buf, int nbytes);

/**
 * TCP checksum -- not really used
 */
uint16_t
tcp_checksum(struct ip* ip_hdr, struct tcphdr* tcphdr);

/**
 * dumps an arbtrary chunk of bytes and prints out printable characters
 */
void
hexdump(const char* const desc, const void* const addr, int len);


#endif /* UTILITY_H */
