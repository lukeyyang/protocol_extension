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
#include "utility.h"

#define FAILURE -1
const static size_t kPKT_MAX_LEN = 1024;
const static size_t kIP_HDR_LEN = 20;
const static size_t kTCP_HDR_LEN = 20;
const static int kSRC_PORT_DEFAULT = 64000;
const static int kDST_PORT_DEFAULT = 64001;
const static char* kIP_LOCALHOST = "127.0.0.1";
const static char* kPAYLOAD = "Hello";


void print_info()
{
        printf("ARGS: [-h src_addr] [-f src_port] "
               "[-d dst_addr] [-p dst_port]\n"
               "*IMPORTANT*: source address (-h) is by default 127.0.0.1;\n"
               "  unless you are receiving from localhost, you SHOULD change\n"
               "  it to your real IP address\n"
               "*IMPORTANT*: DO NOT re-use the same sending port within about\n"
               "  three minutes\n");
}

/* usage: rawtcp [-h src_addr] [-f src_port] [-d dst_addr] [-p dst_port] */
int
main(int argc, char** argv)
{
        /* Print out some useful information */
        print_info();

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


        /* prepare packet */

        const size_t kTOTAL_LEN = kIP_HDR_LEN + kTCP_HDR_LEN
                                + strlen(kPAYLOAD); /* now with data */

        char pkt[kPKT_MAX_LEN];
        memset(pkt, 0, kPKT_MAX_LEN);

        struct ip* ip_hdr = (struct ip*) pkt;
        struct tcphdr* tcp_hdr = (struct tcphdr*) (pkt + sizeof(struct ip));

        assert(sizeof(struct ip) == kIP_HDR_LEN);
        assert(sizeof(struct tcphdr) == kTCP_HDR_LEN);

        struct sockaddr_in src_in, dst_in; 

       
        /* SET UP TWO SOCKETS */
        int sd = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sd < 0) {
                fprintf(stderr, 
                        "sd = socket() error: %s\n", strerror(errno));
                return FAILURE;
        }
        int sd_normal = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sd_normal < 0) {
                fprintf(stderr, 
                        "sd_normal = socket() error: %s\n", strerror(errno));
                return FAILURE;
        }


        int s = 1;
        int one = 1;
        s = setsockopt(sd_normal, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (s < 0) {
                fprintf(stderr,
                        "setsockopt() error: %s\n", strerror(errno));
                return FAILURE;
        }

        s = setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        if (s < 0) {
                fprintf(stderr, "setsockopt() error: %s\n", strerror(errno));
                return FAILURE;
        }

        src_in.sin_family = AF_INET;
        dst_in.sin_family = AF_INET;

        src_in.sin_port = htons(src_port);
        dst_in.sin_port = htons(dst_port);

        src_in.sin_addr.s_addr = inet_addr(src_addr);
        if (src_in.sin_addr.s_addr == INADDR_NONE) {
                fprintf(stderr, "malformed inet_addr() request\n");
                return FAILURE;
        }
        dst_in.sin_addr.s_addr = inet_addr(dst_addr);
        if (dst_in.sin_addr.s_addr == INADDR_NONE) {
                fprintf(stderr, "malformed inet_addr() request\n");
                return FAILURE;
        }


        /* FILL OUT IP HEADER */

        ip_hdr->ip_hl = 5;  /* Internet Header Length */
        ip_hdr->ip_v  = 4;  /* Version */
        ip_hdr->ip_tos = 0; /* Type of service */
        ip_hdr->ip_id = htons(0);  /* identification: unused */
        ip_hdr->ip_len = kTOTAL_LEN; /* Length */ 

        char ip_flags[4];
        memset(ip_flags, 0, 4);

        ip_hdr->ip_off = htons((ip_flags[0] << 15)
                             + (ip_flags[1] << 14)
                             + (ip_flags[2] << 13)
                             +  ip_flags[3]);
        ip_hdr->ip_ttl = 255;

        ip_hdr->ip_p = IPPROTO_TCP;

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
        /* internet_checksum(
               (uint16_t*) pkt, kIP_HDR_LEN + kTCP_HDR_LEN); */

        
        /* FILL OUT TCP HEADER */
        /* cygwin uses BSD flavor header */
#if defined(THIS_IS_OS_X) || defined(THIS_IS_CYGWIN)
        tcp_hdr->th_sport = htons(src_port);  /* TCP source port */
        tcp_hdr->th_dport = htons(dst_port);  /* TCP dest port */
        tcp_hdr->th_seq   = htonl(0);         /* Sequence number */
        tcp_hdr->th_ack   = htonl(0);         /* Acknowledgement number */
        tcp_hdr->th_x2    = 0;                /* unused */
        tcp_hdr->th_off   = kTCP_HDR_LEN / 4; /* Data offset in 32-bit words */
        tcp_hdr->th_flags = 0; /*TH_SYN;*/    /* Flags */
        /**
         * TH_CWR|TH_ECE|TH_URG|TH_ACK|TH_PSH|TH_RST|TH_SYN|TH_FIN
         *   0      0      0      0      0      0      0      0
         */
        tcp_hdr->th_win   = htons(65535);     /* Window */
        tcp_hdr->th_urp   = htons(0);         /* Urgent pointer */
        tcp_hdr->th_sum   = 0; /* htons(tcp_checksum(ip_hdr, tcp_hdr)); */
#elif defined(THIS_IS_LINUX)
        tcp_hdr->source  = htons(src_port);   /* TCP source port */
        tcp_hdr->dest    = htons(dst_port);   /* TCP dest port */
        tcp_hdr->seq     = htonl(0);          /* Sequence number */
        tcp_hdr->ack_seq = htonl(0);          /* Acknowledgement number */
        tcp_hdr->res1    = 0;                 /* unused */
        tcp_hdr->doff    = kTCP_HDR_LEN / 4;  /* Data offset in 32-bit words */
        tcp_hdr->fin     = 0;
        tcp_hdr->syn     = 0; /*1;*/          /* SYN */
        tcp_hdr->rst     = 0;
        tcp_hdr->psh     = 0;
        tcp_hdr->ack     = 0;
        tcp_hdr->urg     = 0;
        tcp_hdr->res2    = 0;
        tcp_hdr->window  = htons(65535);       /* Window */
        tcp_hdr->urg_ptr = htons(0);           /* Urgent pointer */
        tcp_hdr->check   = 0; /* htons(tcp_checksum(ip_hdr, tcp_hdr)); */
#else
  #error "Undetected OS. See include/os_detect.h"
#endif

        /* stuff in some data */
        char* payload = pkt + sizeof(struct ip) + sizeof(struct tcphdr);
        memcpy(payload, kPAYLOAD, strlen(kPAYLOAD));

        
        printf("About to send\n");
        printf("This program will attempt to send our special packet 3\n"
               "times, establish a TCP connection on the same socket,\n"
               "send out a test message in a normal way, pause for 5\n"
               "seconds, and send our special again for 3 times.\n");

        /* initial attempt to send the special packet */

        int i;
        for (i = 0; i < 3; i++) {
                if (sendto(sd, pkt, kTOTAL_LEN, 0, 
                    (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                        fprintf(stderr, "sendto() error: %s\n", strerror(errno));
                        close(sd);
                        return FAILURE;
                } else {
                        printf("%d - first group of special packet attempt"
                               " - sendto() OK.\n", i);
                        sleep(1);
                }
        }

        /* establish a tcp connection the normal way */

        s = bind(sd_normal, (struct sockaddr*) &src_in, sizeof(src_in));
        if (s < 0) {
                fprintf(stderr,
                        "bind() error: %s\n", strerror(errno));
                close(sd_normal);
                return FAILURE;
        }
        s = connect(sd_normal, (struct sockaddr*) &dst_in, sizeof(dst_in));
        if (s < 0) {
                fprintf(stderr, "connect() error: %s\n", strerror(errno));
                close(sd_normal);
                return FAILURE;
        }


        char content[23] = "Connection established";
        content[22] = 0;  // null terminated 
        s = send(sd_normal, content, strlen(content), 0);
        if (s < 0) {
                fprintf(stderr, "send() error: %s\n", strerror(errno));
        } else {
                fprintf(stderr, "send() OK.\n");
                sleep(5);
        }

        /* second attempt to send the special packet */

        for (i = 0; i < 3; i++) {
                if (sendto(sd, pkt, kTOTAL_LEN, 0, 
                    (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                        fprintf(stderr, "sendto() error: %s\n", strerror(errno));
                        close(sd);
                        return FAILURE;
                } else {
                        printf("%d - second group of special packet attempt"
                               " - sendto() OK.\n", i);
                        sleep(1);
                }
        }

        close(sd_normal);
        close(sd);
        return 0;
}
