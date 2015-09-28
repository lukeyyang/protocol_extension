#include <netinet/tcp.h>
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
const static size_t kIP_HDR_LEN = 20;
const static size_t kTCP_HDR_LEN = 20;
const static size_t kTOTAL_LEN = kIP_HDR_LEN + kTCP_HDR_LEN;
const static int kSRC_PORT = 64000;
const static int kDST_PORT = 64001;
const static char* kSRC_ADDR = "192.168.2.1";
const static char* kDST_ADDR = "192.168.2.2";

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

// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t
tcp4_checksum (struct ip* ip_hdr, struct tcphdr* tcp_hdr)
{
        uint16_t svalue;
        char buf[kPKT_MAX_LEN], cvalue;
        char *ptr;
        int chksumlen = 0;

        // ptr points to beginning of buffer buf
        ptr = &buf[0];

        // Copy source IP address into buf (32 bits)
        memcpy (ptr, &(ip_hdr->ip_src.s_addr), sizeof(ip_hdr->ip_src.s_addr));
        ptr += sizeof (ip_hdr->ip_src.s_addr);
        chksumlen += sizeof (ip_hdr->ip_src.s_addr);

        // Copy destination IP address into buf (32 bits)
        memcpy (ptr, &(ip_hdr->ip_dst.s_addr), sizeof (ip_hdr->ip_dst.s_addr));
        ptr += sizeof (ip_hdr->ip_dst.s_addr);
        chksumlen += sizeof (ip_hdr->ip_dst.s_addr);

        // Copy zero field to buf (8 bits)
        *ptr = 0; 
        ptr++;
        chksumlen += 1;

        // Copy transport layer protocol to buf (8 bits)
        memcpy (ptr, &(ip_hdr->ip_p), sizeof (ip_hdr->ip_p));
        ptr += sizeof (ip_hdr->ip_p);
        chksumlen += sizeof (ip_hdr->ip_p);

        // Copy TCP length to buf (16 bits)
        svalue = htons (sizeof (tcp_hdr));
        memcpy (ptr, &svalue, sizeof (svalue));
        ptr += sizeof (svalue);
        chksumlen += sizeof (svalue);

        // Copy TCP source port to buf (16 bits)
        memcpy (ptr, &(tcp_hdr->th_sport), sizeof (tcp_hdr->th_sport));
        ptr += sizeof (tcp_hdr->th_sport);
        chksumlen += sizeof (tcp_hdr->th_sport);

        // Copy TCP destination port to buf (16 bits)
        memcpy (ptr, &(tcp_hdr->th_dport), sizeof (tcp_hdr->th_dport));
        ptr += sizeof (tcp_hdr->th_dport);
        chksumlen += sizeof (tcp_hdr->th_dport);

        // Copy sequence number to buf (32 bits)
        memcpy (ptr, &(tcp_hdr->th_seq), sizeof (tcp_hdr->th_seq));
        ptr += sizeof (tcp_hdr->th_seq);
        chksumlen += sizeof (tcp_hdr->th_seq);

        // Copy acknowledgement number to buf (32 bits)
        memcpy (ptr, &(tcp_hdr->th_ack), sizeof (tcp_hdr->th_ack));
        ptr += sizeof (tcp_hdr->th_ack);
        chksumlen += sizeof (tcp_hdr->th_ack);

        // Copy data offset to buf (4 bits) and
        // copy reserved bits to buf (4 bits)
        cvalue = (tcp_hdr->th_off << 4) + tcp_hdr->th_x2;
        memcpy (ptr, &cvalue, sizeof (cvalue));
        ptr += sizeof (cvalue);
        chksumlen += sizeof (cvalue);

        // Copy TCP flags to buf (8 bits)
        memcpy (ptr, &(tcp_hdr->th_flags), sizeof (tcp_hdr->th_flags));
        ptr += sizeof (tcp_hdr->th_flags);
        chksumlen += sizeof (tcp_hdr->th_flags);

        // Copy TCP window size to buf (16 bits)
        memcpy (ptr, &(tcp_hdr->th_win), sizeof (tcp_hdr->th_win));
        ptr += sizeof (tcp_hdr->th_win);
        chksumlen += sizeof (tcp_hdr->th_win);

        // Copy TCP checksum to buf (16 bits)
        // Zero, since we don't know it yet
        *ptr = 0; 
        ptr++;
        *ptr = 0; 
        ptr++;
        chksumlen += 2;

        // Copy urgent pointer to buf (16 bits)
        memcpy (ptr, &(tcp_hdr->th_urp), sizeof (tcp_hdr->th_urp));
        ptr += sizeof (tcp_hdr->th_urp);
        chksumlen += sizeof (tcp_hdr->th_urp);

        return checksum ((uint16_t *) buf, chksumlen);
}

int
main(void)
{
        char pkt[kPKT_MAX_LEN];
        memset(pkt, 0, kPKT_MAX_LEN);

        struct ip* ip_hdr = (struct ip*) pkt;
        struct tcphdr* tcp_hdr = (struct tcphdr*) (pkt + sizeof(struct ip));

        assert(sizeof(struct ip) == kIP_HDR_LEN);
        assert(sizeof(struct tcphdr) == kTCP_HDR_LEN);

        struct sockaddr_in sin, din;
        int one = 1;

       
        /* SET UP SOCKET */
        int sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
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
        din.sin_family = AF_INET;

        sin.sin_port = htons(kSRC_PORT);
        din.sin_port = htons(kDST_PORT);

        sin.sin_addr.s_addr = inet_addr(kSRC_ADDR);
        din.sin_addr.s_addr = inet_addr(kDST_ADDR);



        /* FILL OUT IP HEADER */

        ip_hdr->ip_hl = 5;  /* Internet Header Length */
        ip_hdr->ip_v  = 4;  /* Version */
        ip_hdr->ip_tos = 0; /* Type of service */
        ip_hdr->ip_id = htons(0);  /* identification: unused */
        ip_hdr->ip_len = kTOTAL_LEN; /* Length */

        char ip_flags[4];
        memset(ip_flags, 4, 0);

        ip_hdr->ip_off = htons((ip_flags[0] << 15)
                             + (ip_flags[1] << 14)
                             + (ip_flags[2] << 13)
                             +  ip_flags[3]);
        ip_hdr->ip_ttl = 255;

        ip_hdr->ip_p = IPPROTO_TCP;

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

        ip_hdr->ip_sum = 0;//checksum((uint16_t*) pkt, kIP_HDR_LEN + kTCP_HDR_LEN);

        
        /* FILL OUT TCP HEADER */

        tcp_hdr->th_sport = htons(kSRC_PORT); /* TCP source port */
        tcp_hdr->th_dport = htons(kDST_PORT); /* TCP dest port */
        tcp_hdr->th_seq = htonl(0);           /* Sequence number */
        tcp_hdr->th_ack = htonl(0);           /* Acknowledgement number */
        tcp_hdr->th_x2 = 0;                   /* unused */
        tcp_hdr->th_off = kTCP_HDR_LEN / 4;   /* Data offset */
        tcp_hdr->th_flags = TH_SYN;                /* Flags */
        /**
         * TH_CWR|TH_ECE|TH_URG|TH_ACK|TH_PSH|TH_RST|TH_SYN|TH_FIN
         *   0      0      0      0      0      0      0      0
         */
        tcp_hdr->th_win = htons(65535);       /* Window */
        tcp_hdr->th_urp = htons(0);           /* Urgent pointer */
        tcp_hdr->th_sum = htons(tcp4_checksum(ip_hdr, tcp_hdr));




        
        printf("About to send\n");


        int i;
        for (i = 0; i < 10; i++) {
                if (sendto(sd, pkt, kTOTAL_LEN, 0, 
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
