#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include "os_detect.h"
#include "utility.h"

#define kUSAGE "usage: %s [-h source_addr]"\
                         "[-f source_port]"\
                         "[-d dest_addr]"\
                         "[-p dest_port]\n"
const static size_t kPKT_MAX_LEN = 1024;

/* process command line arguments */
void 
parse_args(int argc,
           char* const argv[],
           char* const source_addr,
           int* const source_port,
           char* const dest_addr,
           int* const dest_port)
{
        const static char* usage = kUSAGE;
        const static size_t kIPADDR_MAXLEN = 16;
        int ch = -1;
        int num = 0;
        while ((ch = getopt(argc, argv, "h:f:d:p:")) != -1) {
                switch (ch) {
                case 'h':
                        strncpy(source_addr, optarg, kIPADDR_MAXLEN);
                        break;
                case 'f':
                        num = (int) strtol(optarg, NULL, 10);
                        if ((!num) && (errno == EINVAL || errno == ERANGE)) {
                                fprintf(stderr,
                                        "Invalid source port number, "
                                        "reset to default 64000\n");
                        } else {
                                *source_port = num;
                        }
                        break;
                case 'd':
                        strncpy(dest_addr, optarg, kIPADDR_MAXLEN);
                        break;
                case 'p':
                        num = (int) strtol(optarg, NULL, 10);
                        if ((!num) && (errno == EINVAL || errno == ERANGE)) {
                                fprintf(stderr,
                                        "Invalid destination port number, "
                                        "reset to default 64001\n");
                        } else {
                                *dest_port = num;
                        }
                        break;
                case '?':
                default:
                        fprintf(stderr, usage, argv[0]);
                        exit(-1);
                        break;
                }
        }
}


/* internet checksum */
uint16_t 
internet_checksum(uint16_t* buf, int nbytes)
{
        uint64_t sum = 0;
        int nbytes2 = nbytes;
        for (; nbytes2 > 1; nbytes2 -= 2) {
                sum += *(buf++);
        }
        if (nbytes2 > 0) {
                sum += *((uint8_t*)buf);
        }
        while (sum >> 16) {
                sum = (sum >> 16) + (sum & 0xffff);
        }
        return (uint16_t)(~sum);
}

/**
 * Build IPv4 TCP pseudo-header and call checksum function.
 * NOTE: not a generic algorithm, see below 
 */
uint16_t
tcp_checksum(struct ip* ip_hdr, struct tcphdr* tcp_hdr)
{
        uint16_t svalue;  /* TCP segment length, 16 bits */
        char buf[kPKT_MAX_LEN], cvalue;
        char *ptr = &buf[0];
        int chksumlen = 0;

        /* pull data from IP header */

        /* Copy source IP address into buf (32 bits) */
        memcpy(ptr, &(ip_hdr->ip_src.s_addr), sizeof(ip_hdr->ip_src.s_addr));
        ptr += sizeof(ip_hdr->ip_src.s_addr);
        chksumlen += sizeof(ip_hdr->ip_src.s_addr);

        /* Copy destination IP address into buf (32 bits) */
        memcpy(ptr, &(ip_hdr->ip_dst.s_addr), sizeof(ip_hdr->ip_dst.s_addr));
        ptr += sizeof(ip_hdr->ip_dst.s_addr);
        chksumlen += sizeof(ip_hdr->ip_dst.s_addr);

        /* Copy zero field to buf -- reserved field -- (8 bits) */
        *ptr = 0; 
        ptr++;
        chksumlen += 1;

        /* Copy transport layer protocol to buf (8 bits) */
        memcpy(ptr, &(ip_hdr->ip_p), sizeof(ip_hdr->ip_p));
        ptr += sizeof(ip_hdr->ip_p);
        chksumlen += sizeof(ip_hdr->ip_p);

        /**
         * Copy TCP length to buf (16 bits) 
         * NOTE: Since we don't put actual data in the packet
         * Segment length is TCP header length
         */
        svalue = htons(sizeof(*tcp_hdr)); 
        memcpy(ptr, &svalue, sizeof(svalue));
        ptr += sizeof(svalue);
        chksumlen += sizeof(svalue);

        /* pull data from TCP header */

#ifdef THIS_IS_OS_X

        /* Copy TCP source port to buf (16 bits) */
        memcpy(ptr, &(tcp_hdr->th_sport), sizeof(tcp_hdr->th_sport));
        ptr += sizeof(tcp_hdr->th_sport);
        chksumlen += sizeof(tcp_hdr->th_sport);

        /* Copy TCP destination port to buf (16 bits) */
        memcpy(ptr, &(tcp_hdr->th_dport), sizeof(tcp_hdr->th_dport));
        ptr += sizeof(tcp_hdr->th_dport);
        chksumlen += sizeof(tcp_hdr->th_dport);

        /* Copy sequence number to buf (32 bits) */
        memcpy(ptr, &(tcp_hdr->th_seq), sizeof(tcp_hdr->th_seq));
        ptr += sizeof(tcp_hdr->th_seq);
        chksumlen += sizeof(tcp_hdr->th_seq);

        /* Copy acknowledgement number to buf (32 bits) */
        memcpy(ptr, &(tcp_hdr->th_ack), sizeof(tcp_hdr->th_ack));
        ptr += sizeof(tcp_hdr->th_ack);
        chksumlen += sizeof(tcp_hdr->th_ack);

        /**
         * Copy data offset to buf (4 bits) and
         * copy reserved bits to buf (4 bits)
         */
        cvalue = (tcp_hdr->th_off << 4) + tcp_hdr->th_x2;
        memcpy(ptr, &cvalue, sizeof (cvalue));
        ptr += sizeof(cvalue);
        chksumlen += sizeof(cvalue);

        /* Copy TCP flags to buf (8 bits) */
        memcpy(ptr, &(tcp_hdr->th_flags), sizeof(tcp_hdr->th_flags));
        ptr += sizeof(tcp_hdr->th_flags);
        chksumlen += sizeof(tcp_hdr->th_flags);

        /* Copy TCP window size to buf (16 bits) */
        memcpy(ptr, &(tcp_hdr->th_win), sizeof(tcp_hdr->th_win));
        ptr += sizeof(tcp_hdr->th_win);
        chksumlen += sizeof(tcp_hdr->th_win);

#elif defined(THIS_IS_LINUX)

        /* Copy TCP source port to buf (16 bits) */
        memcpy(ptr, &(tcp_hdr->source), sizeof(tcp_hdr->source));
        ptr += sizeof(tcp_hdr->source);
        chksumlen += sizeof(tcp_hdr->source);

        /* Copy TCP destination port to buf (16 bits) */
        memcpy(ptr, &(tcp_hdr->dest), sizeof(tcp_hdr->dest));
        ptr += sizeof(tcp_hdr->dest);
        chksumlen += sizeof(tcp_hdr->dest);

        /* Copy sequence number to buf (32 bits) */
        memcpy(ptr, &(tcp_hdr->seq), sizeof(tcp_hdr->seq));
        ptr += sizeof(tcp_hdr->seq);
        chksumlen += sizeof(tcp_hdr->seq);

        /* Copy acknowledgement number to buf (32 bits) */
        memcpy(ptr, &(tcp_hdr->ack_seq), sizeof(tcp_hdr->ack_seq));
        ptr += sizeof(tcp_hdr->ack_seq);
        chksumlen += sizeof(tcp_hdr->ack_seq);

        /**
         * Copy data offset to buf (4 bits) and
         * copy reserved bits to buf (4 bits)
         */
        cvalue = (tcp_hdr->doff << 4) + tcp_hdr->res1;
        memcpy(ptr, &cvalue, sizeof(cvalue));
        ptr += sizeof(cvalue);
        chksumlen += sizeof(cvalue);

        /* Copy TCP flags to buf (8 bits) */

        memcpy(ptr, (void*) tcp_hdr + 16, 1);
        ptr += 1;
        chksumlen += 1;

        /* Copy TCP window size to buf (16 bits) */
        memcpy(ptr, &(tcp_hdr->window), sizeof(tcp_hdr->window));
        ptr += sizeof(tcp_hdr->window);
        chksumlen += sizeof(tcp_hdr->window);

#else
  #error "Undetected OS. See os_detect.h"
#endif

        /**
         * Copy TCP checksum to buf (16 bits)
         * Zero for now, since we don't know it yet
         */
        *ptr = 0; 
        ptr++;
        *ptr = 0; 
        ptr++;
        chksumlen += 2;

        /* Copy urgent pointer to buf (16 bits) */
#ifdef THIS_IS_OS_X
        memcpy(ptr, &(tcp_hdr->th_urp), sizeof(tcp_hdr->th_urp));
        ptr += sizeof(tcp_hdr->th_urp);
        chksumlen += sizeof(tcp_hdr->th_urp);
#elif defined(THIS_IS_LINUX)
        memcpy(ptr, &(tcp_hdr->urg_ptr), sizeof(tcp_hdr->urg_ptr));
        ptr += sizeof(tcp_hdr->urg_ptr);
        chksumlen += sizeof(tcp_hdr->urg_ptr);
#else
  #error "Undetected OS. See os_detect.h"
#endif

        return internet_checksum((uint16_t*) buf, chksumlen);
}


