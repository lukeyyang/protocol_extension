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

#define FAILURE -1
const static size_t kPKT_MAX_LEN = 1024;
const static size_t kTRAILER_OFFSET = 4;
const static size_t kOPTIONS_LENGTH = 12;
const static size_t kIP_HDR_LEN = 20;
const static size_t kUDP_HDR_LEN = 8;
const static int kSRC_PORT = 64000;
const static int kDST_PORT = 64001;
const static char* kSRC_ADDR = "192.168.2.1";
const static char* kDST_ADDR = "192.168.1.7";

uint16_t 
checksum(uint16_t* buffer, int nwords)
{
        uint64_t sum;
        for (sum = 0; nwords > 0; nwords--) {
                sum += *buffer;
                buffer++;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += sum >> 16;
        return (uint16_t)(~sum);
}

int
main(void)
{
        const size_t kTOTAL_PKT_LEN = kIP_HDR_LEN + kUDP_HDR_LEN
                                    + kTRAILER_OFFSET + kOPTIONS_LENGTH;

        char pkt[kPKT_MAX_LEN];
        memset(pkt, 0, kPKT_MAX_LEN);

        struct ip* ip_hdr = (struct ip*) pkt;
        struct udphdr* udp_hdr = (struct udphdr*) (pkt + sizeof(struct ip));

        assert(sizeof(struct ip) == kIP_HDR_LEN);
        assert(sizeof(struct udphdr) == kUDP_HDR_LEN);

        struct sockaddr_in sin; /*, din; */
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

        sin.sin_family = AF_INET;
        /* din.sin_family = AF_INET; */

        sin.sin_port = htons(kSRC_PORT);
        /* din.sin_port = htons(kDST_PORT); */

        sin.sin_addr.s_addr = inet_addr(kSRC_ADDR);
        /* din.sin_addr.s_addr = inet_addr(kDST_ADDR); */

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

        s = inet_pton(AF_INET, kSRC_ADDR, &(ip_hdr->ip_src));
        if (s != 1) {
                fprintf(stderr, "inet_pton() error: %s\n", strerror(errno));
                return FAILURE;
        }
        s = inet_pton(AF_INET, kDST_ADDR, &(ip_hdr->ip_dst));
        if (s != 1) {
                fprintf(stderr, "inet_pton() error: %s\n", strerror(errno));
                return FAILURE;
        }

        ip_hdr->ip_sum = 0;
        /* checksum((uint16_t*) pkt, kIP_HDR_LEN + kUDP_HDR_LEN); */

        
        /* FILL OUT UDP HEADER */

#ifdef THIS_IS_OS_X
        udp_hdr->uh_sport = htons(kSRC_PORT); /* UDP source port */
        udp_hdr->uh_dport = htons(kDST_PORT); /* UDP dest port */
        udp_hdr->uh_ulen  = htons(kUDP_HDR_LEN + kTRAILER_OFFSET);
        udp_hdr->uh_sum   = 0;
#elif defined(THIS_IS_LINUX)
        udp_hdr->source = htons(kSRC_PORT); /* UDP source port */
        udp_hdr->dest   = htons(kDST_PORT); /* UDP dest port */
        udp_hdr->len    = htons(kUDP_HDR_LEN + kTRAILER_OFFSET);
        udp_hdr->check  = 0;
#else
  #error "Undetected OS. See os_detect.h"
#endif

        /* MOVE PAYLOAD IN PLACE */

        memcpy(pkt + kIP_HDR_LEN + kUDP_HDR_LEN, udp_payload, kTRAILER_OFFSET);
        memcpy(pkt + kIP_HDR_LEN + kUDP_HDR_LEN + kTRAILER_OFFSET,
            udp_options, kOPTIONS_LENGTH);

        
        printf("About to send\n");
        int i;
        for (i = 0; i < 10; i++) {
                if (sendto(sd, pkt, kTOTAL_PKT_LEN, 0, 
                    (struct sockaddr *)&sin, sizeof(sin)) < 0) {
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
