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
#include "constant.h"

#define FAILURE -1


void 
print_info()
{
        printf("ARGS: [-h src_addr] [-f src_port] "
               "[-d dst_addr] [-p dst_port]\n"
               "*IMPORTANT*: source address (-h) is by default 127.0.0.1;\n"
               "  unless you are receiving from localhost, you SHOULD change\n"
               "  it to your real IP address\n"
               "*IMPORTANT*: DO NOT re-use the same sending port within about\n"
               "  three minutes\n");
}


/* usage: twhs_client [-h src_addr] [-f src_port] [-d dst_addr] [-p dst_port] */
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


        /* prepare address data structure */

        struct sockaddr_in src_in, dst_in; 
        bzero(&src_in, sizeof(src_in));
        bzero(&dst_in, sizeof(dst_in));

        src_in.sin_family = AF_INET;
        dst_in.sin_family = AF_INET;

        src_in.sin_port = htons(src_port);
        dst_in.sin_port = htons(dst_port);

        src_in.sin_addr.s_addr = htonl(INADDR_ANY);
        dst_in.sin_addr.s_addr = inet_addr(dst_addr);
        if (dst_in.sin_addr.s_addr == INADDR_NONE) {
                fprintf(stderr, "malformed inet_addr() request\n");
                return FAILURE;
        }
     
        /* get a socket to play with */
        int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sd < 0) {
                fprintf(stderr, 
                        "sd = socket() error: %s\n", strerror(errno));
                return FAILURE;
        }

        int s = 1;
        int one = 1;
        
        /* set the socket to be on raw IP level */
        s = setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        if (s < 0) {
                fprintf(stderr, 
                        "setsockopt() error: %s\n", strerror(errno));
                close(sd);
                return FAILURE;
        }

        
        printf("About to start experiment\n");
        printf("This program will send an OOB packet and wait for 3 sec. \n"
               "Then, it sends a SYN packet, wait for 1 second, and sends \n"
               "an OOB packet again. The receiver is expected to return \n"
               "a SYN-ACK packet 5 seconds after it receives the SYN. When \n"
               "this program receives the SYN-ACK, it sends the OOB again.\n");

        /* prepare packet */

        char* syn_pkt = malloc(kPKT_MAX_LEN);
        char* oob_pkt = malloc(kPKT_MAX_LEN);
        memset(syn_pkt, 0, kPKT_MAX_LEN);
        memset(oob_pkt, 0, kPKT_MAX_LEN);

        prepare_tcp_pkt(kPKT_TYPE_SYN, 
                        &syn_pkt, src_port, dst_port, src_addr, dst_addr);
        prepare_tcp_pkt(kPKT_TYPE_OOB,
                        &oob_pkt, src_port, dst_port, src_addr, dst_addr);

        const size_t kSYN_PKT_LEN = kIP_HDR_LEN + kTCP_HDR_LEN;
        const size_t kOOB_PKT_LEN = kIP_HDR_LEN + kTCP_HDR_LEN
                                 + strlen(kPAYLOAD); /* now with data */

        /* OOB first */

        if (sendto(sd, oob_pkt, kOOB_PKT_LEN , 0, 
                   (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                fprintf(stderr, "sendto() error: %s\n", strerror(errno));
                free(syn_pkt);
                free(oob_pkt);
                close(sd);
                return FAILURE;
        } else {
                printf("\tOOB packet successfully sent; about to SYN\n");
                sleep(3);
        }


        /* SYN first */

        if (sendto(sd, syn_pkt, kSYN_PKT_LEN, 0, 
                   (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                fprintf(stderr, "sendto() error: %s\n", strerror(errno));
                free(syn_pkt);
                free(oob_pkt);
                close(sd);
                return FAILURE;
        } else {
                printf("\tSYN packet successfully sent; wait for a sec...\n");
                free(syn_pkt);
                syn_pkt = NULL;
                sleep(1);
        }

        /* now OOB again */
        memset(oob_pkt, 0, kPKT_MAX_LEN);
        prepare_tcp_pkt(kPKT_TYPE_OOB,
                        &oob_pkt, src_port, dst_port, src_addr, dst_addr);


        if (sendto(sd, oob_pkt, kOOB_PKT_LEN , 0, 
                   (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                fprintf(stderr, "sendto() error: %s\n", strerror(errno));
                free(oob_pkt);
                close(sd);
                return FAILURE;
        } else {
                printf("\tOOB packet successfully sent; wait for SYN-ACK\n");
        }

        /* wait for SYNACK */

        /* get another socket to play with */
        int sd2 = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sd2 < 0) {
                fprintf(stderr, 
                        "sd2 = socket() error: %s\n", strerror(errno));
                return FAILURE;
        }

        /* set this socket to be on raw IP level */
        s = setsockopt(sd2, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        if (s < 0) {
                fprintf(stderr, 
                        "setsockopt() error: %s\n", strerror(errno));
                close(sd2);
                return FAILURE;
        }
 
        /* bind the socket to src_port
         * NOTE if I don't bind() here, use read() below should work, too
         */
        s = bind(sd2, (struct sockaddr*) &src_in, sizeof(src_in));
        if (s < 0) {
                fprintf(stderr,
                        "bind() error: %s\n", strerror(errno));
                close(sd);
                return FAILURE;
        }

        /* receive SYNACK */
        int n = -1;
        char msg[kBUFFER_MAX_LEN];
        bzero(msg, kBUFFER_MAX_LEN);
        socklen_t len = sizeof(dst_in);
        /* NOTE if I use sd instead of sd2 here, I will get the OOB packet that
         * I sent earlier. I don't know why.
         */
        n = recvfrom(sd2, msg, kBUFFER_MAX_LEN, 0, 
                        (struct sockaddr*) &dst_in, &len);
        if (n < 0) {
                fprintf(stderr,
                        "recvfrom() error: %s\n", strerror(errno));
                free(oob_pkt);
                close(sd);
                return FAILURE;
        } else {
                printf("Received %d bytes\n", n);
                hexdump("received_packet", (void*) msg, n);
        }
        
        /* integrity check */
        if (n < kIP_HDR_LEN + kTCP_HDR_LEN) {
                fprintf(stderr,
                        "fatal: header length incomplete\n");
                free(oob_pkt);
                close(sd);
                return FAILURE;
        }
        
        struct ip* ip_hdr = (struct ip*) msg;
        if ((ip_hdr->ip_hl != 5) || (ip_hdr->ip_v != 4)) {
                fprintf(stderr,
                        "fatal: IP header corrupt\n");
                free(oob_pkt);
                close(sd);
                return FAILURE;
        }
        if (ntohs(ip_hdr->ip_len) != n) {
                fprintf(stderr,
                        "fatal: IP header indicates a different "
                        "byte count from read(): %d\n", 
                        ntohs(ip_hdr->ip_len));
                free(oob_pkt);
                close(sd);
                return FAILURE;
        }
        if (ip_hdr->ip_p != IPPROTO_TCP) {
                fprintf(stderr,
                        "fatal: IP header says it's not "
                        "a TCP packet\n");
                free(oob_pkt);
                close(sd);
                return FAILURE;
        }
        char incoming_src_addr[16];
        char incoming_dst_addr[16];
        memset(incoming_src_addr, 0, 16);
        memset(incoming_dst_addr, 0, 16);

        inet_ntop(AF_INET, &(ip_hdr->ip_src), incoming_src_addr, 16);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), incoming_dst_addr, 16);

        /* check for SYNACK flags */
        struct tcphdr* tcp_hdr
                = (struct tcphdr*) (msg + sizeof(struct ip));

        printf("received TCP packet from %s:%u to %s:%u\n", 
#if defined(THIS_IS_OS_X) || defined(THIS_IS_CYGWIN)
            incoming_src_addr, 
            ntohs(tcp_hdr->th_sport), 
            incoming_dst_addr,
            ntohs(tcp_hdr->th_dport)
#elif defined(THIS_IS_LINUX)
            incoming_src_addr, 
            ntohs(tcp_hdr->source),
            incoming_dst_addr,
            ntohs(tcp_hdr->dest)
#else
  #error "Undetected OS. See include/os_detect.h"
#endif
        );
                    


        if (
#if defined(THIS_IS_OS_X) || defined(THIS_IS_CYGWIN)
            tcp_hdr->th_flags == (TH_SYN | TH_ACK)
#elif defined(THIS_IS_LINUX)
            tcp_hdr->syn == 1 && tcp_hdr->ack == 1
#else
  #error "Undetected OS. See include/os_detect.h"
#endif
           ) {
                printf("this is a SYN-ACK packet. Send OOB again.\n");
                sleep(1);

                memset(oob_pkt, 0, kPKT_MAX_LEN);
                prepare_tcp_pkt(kPKT_TYPE_OOB,
                        &oob_pkt, src_port, dst_port, src_addr, dst_addr);


                if (sendto(sd, oob_pkt, kOOB_PKT_LEN , 0, 
                           (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                        fprintf(stderr, "sendto() error: %s\n", strerror(errno));
                        free(oob_pkt);
                        close(sd);
                        return FAILURE;
                } else {
                        printf("\tOOB packet successfully sent\n");
                }
        } else {
                fprintf(stderr, "unrecognized TCP flag\n");
                free(oob_pkt);
                close(sd);
                close(sd2);
                return FAILURE;
        }


        free(oob_pkt);
        close(sd);
        close(sd2);
        return 0;
}
