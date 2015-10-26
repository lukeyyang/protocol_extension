#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>

#include "os_detect.h"
#include "utility.h"

#define FAILURE -1
const static size_t kPKT_MAX_LEN = 1024;
const static size_t kTRAILER_OFFSET = 4;
const static size_t kOPTIONS_LENGTH = 12;
const static size_t kIP_HDR_LEN = 20;
const static size_t kUDP_HDR_LEN = 8;
const static int kSRC_PORT_DEFAULT = 64000;
const static int kDST_PORT_DEFAULT = 64001;
const static char* kIP_LOCALHOST = "127.0.0.1";


int
main(int argc, char** argv)
{
        /* COMMAND LINE PARSING */

        int src_port = kSRC_PORT_DEFAULT;
        int dst_port = kDST_PORT_DEFAULT;

        char src_addr[16];
        char dst_addr[16];
        memset(src_addr, 0, 16);
        memset(dst_addr, 0, 16);
        strncpy(src_addr, kIP_LOCALHOST, 16);
        strncpy(dst_addr, kIP_LOCALHOST, 16);

        parse_args(argc, argv, src_addr, &src_port, dst_addr, &dst_port);

        printf("src: %s: %d\n", src_addr, src_port);
        printf("dst: %s: %d\n", dst_addr, dst_port);

        const size_t kTOTAL_PKT_LEN = kIP_HDR_LEN + kUDP_HDR_LEN
                                    + kTRAILER_OFFSET + kOPTIONS_LENGTH;

        char pkt[kPKT_MAX_LEN];
        memset(pkt, 0, kPKT_MAX_LEN);

        struct ip* ip_hdr = (struct ip*) pkt;
        struct udphdr* udp_hdr = (struct udphdr*) (pkt + sizeof(struct ip));

        assert(sizeof(struct ip) == kIP_HDR_LEN);
        assert(sizeof(struct udphdr) == kUDP_HDR_LEN);

        struct sockaddr_in dst_in;
        int one = 1;

        /* SET UP SOCKET */
        int sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
        if (sd < 0) {
                fprintf(stderr, "socket() error: %s\n", strerror(errno));
                return FAILURE;
        }

        int s = 1;
        s = setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        if (s < 0) {
                fprintf(stderr, "setsockopt() error: %s\n", strerror(errno));
                return FAILURE;
        }

        dst_in.sin_family = AF_INET;

        dst_in.sin_port = htons(src_port);

        dst_in.sin_addr.s_addr = inet_addr(src_addr);
        if (dst_in.sin_addr.s_addr == INADDR_NONE) {
                fprintf(stderr, "malformed inet_addr() request\n");
                return FAILURE;
        }

        /* UDP PAYLOAD AND OPTION AREA */

        unsigned char udp_payload[kTRAILER_OFFSET];
        strncpy((char*) udp_payload, "test", kTRAILER_OFFSET);
        unsigned char udp_options[kOPTIONS_LENGTH];
        memset(udp_options, 0, kOPTIONS_LENGTH);
        udp_options[0] = (unsigned char) 254; /* Experimental kind */
        udp_options[1] = (unsigned char) 16; /* length, required >= 4 */


        /* FILL OUT IP HEADER */

        ip_hdr->ip_hl = 5;  /* Internet Header Length */
        ip_hdr->ip_v  = 4;  /* Version */
        ip_hdr->ip_tos = 0; /* Type of service */
        ip_hdr->ip_len = kTOTAL_PKT_LEN; /* Length */
        ip_hdr->ip_id = htons(0);  /* identification: unused */

        char ip_flags[4];
        memset(ip_flags, 0, 4);

        ip_hdr->ip_off = htons((ip_flags[0] << 15)
                             + (ip_flags[1] << 14)
                             + (ip_flags[2] << 13)
                             +  ip_flags[3]);
        ip_hdr->ip_ttl = 255;

        ip_hdr->ip_p = IPPROTO_UDP;

        s = inet_pton(AF_INET, src_addr, &(ip_hdr->ip_src));
        if (s != 1) {
                fprintf(stderr, "inet_pton() error: %s\n", strerror(errno));
                return FAILURE;
        }
        s = inet_pton(AF_INET, dst_addr, &(ip_hdr->ip_dst));
        if (s != 1) {
                fprintf(stderr, "inet_pton() error: %s\n", strerror(errno));
                return FAILURE;
        }

        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = internet_checksum((uint16_t*) pkt, kIP_HDR_LEN);

        
        /* FILL OUT UDP HEADER */
        /* checksum intentionally set to 0 */

#ifdef THIS_IS_OS_X
        udp_hdr->uh_sport = htons(src_port); /* UDP source port */
        udp_hdr->uh_dport = htons(dst_port); /* UDP dest port */
        udp_hdr->uh_ulen  = htons(kUDP_HDR_LEN + kTRAILER_OFFSET);
        udp_hdr->uh_sum   = 0;
#elif defined(THIS_IS_LINUX)
        udp_hdr->source = htons(src_port); /* UDP source port */
        udp_hdr->dest   = htons(dst_port); /* UDP dest port */
        udp_hdr->len    = htons(kUDP_HDR_LEN + kTRAILER_OFFSET);
        udp_hdr->check  = 0;
#else
  #error "Undetected OS. See os_detect.h"
#endif

        /* MOVE PAYLOAD IN PLACE */

        memcpy(pkt + kIP_HDR_LEN + kUDP_HDR_LEN, udp_payload, kTRAILER_OFFSET);
        memcpy(pkt + kIP_HDR_LEN + kUDP_HDR_LEN + kTRAILER_OFFSET,
            udp_options, kOPTIONS_LENGTH);

        
        printf("About to send THREE special packets\n");
        int i;
        for (i = 0; i < 3; i++) {
                if (sendto(sd, pkt, kTOTAL_PKT_LEN, 0, 
                    (struct sockaddr*)&dst_in, sizeof(dst_in)) < 0) {
                        fprintf(stderr, "sendto() error: %s\n", strerror(errno));
                        return FAILURE;
                } else {
                        printf("%d - sendto() OK.\n", i);
                        sleep(1);
                }
        }

        close(sd);
        return 0;
}
