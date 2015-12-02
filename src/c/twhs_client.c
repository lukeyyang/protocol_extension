/**
 * twhs_client.c
 * client code for sending TCP OOB packet before and during a TCP connection
 * usage:
 *   twhs_client [-h src_addr] [-f src_port] [-d dst_addr] [-p dst_port] [-v]
 * requires root privilege
 *
 * currently uses two raw IP sockets, one for sending and one for receiving
 * first sends an OOB packets, then sleeps for 3 seconds
 * sends SYN, then sleeps for 1 second
 * sends a second OOB packet, then starts waiting for SYNACK (5 seconds later)
 * sends a final OOB packet after the SYNACK arrives
 * works in pair with twhs_server
 */

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <arpa/inet.h>

#include "os_detect.h"
#include "utility.h"
#include "constant.h"
#include "debug.h"

#define FAILURE -1

#define PEACEOUT_W {\
        close(sfd_w); \
        LOGV("closed sfd_w. shutting down"); \
        return FAILURE; \
}

#define PEACEOUT_OW {\
        FREE_PTR(oob_pkt); \
        LOGV("cleaned up OOB packet"); \
        PEACEOUT_W; \
}

#define PEACEOUT_OWR {\
        FREE_PTR(oob_pkt); \
        LOGV("cleaned up OOB packet"); \
        close(sfd_r); \
        LOGV("closed sfd_r"); \
        PEACEOUT_W; \
}
#define PEACEOUT_SW {\
        FREE_PTR(syn_pkt); \
        LOGV("cleaned up SYN packet"); \
        PEACEOUT_W; \
}
#define PEACEOUT_SOW {\
        FREE_PTR(syn_pkt); \
        LOGV("cleaned up SYN packet"); \
        PEACEOUT_OW; \
}
int
main(int argc, char** argv)
{
        /* parses command line args */
        int src_port = kSRC_PORT_DEFAULT;
        int dst_port = kDST_PORT_DEFAULT;

        char src_addr[16];
        char dst_addr[16];
        memset(src_addr, 0, 16);
        memset(dst_addr, 0, 16);
        strncpy(src_addr, kIP_LOCALHOST, 16);
        strncpy(dst_addr, kIP_LOCALHOST, 16);

        parse_args(argc, argv, 
                        src_addr, &src_port, dst_addr, &dst_port,
                        &verbose);

        if (!strncmp(src_addr, "127.0.0.1", 16)) {
                if (!strncmp(dst_addr, "127.0.0.1", 16)) {
                        LOGW("Source IP address is default value 127.0.0.1. "
                             "This is discouraged. It is only allowed to do "
                             "so if localhost is the destination.");
                } else {
                        LOGX("Sending from 127.0.0.1 to non-localhost IP is "
                             "disallowed.");
                        return FAILURE;
                }
        }

        LOGV("client: %s: %d", src_addr, src_port);
        LOGV("server: %s: %d", dst_addr, dst_port);

        /* prepares address data structure */
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
                LOGX("malformed inet_addr() request");
                return FAILURE;
        }

        LOGV("prepared src and dst data structures");
     
        /* gets a socket to write to */
        int sfd_w = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sfd_w < 0) {
                LOGX("socket()");
                return FAILURE;
        }
        /*  ** declaring the read sfd here leads to problem **
        int sfd_r = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sfd_r < 0) {
                LOGX("socket()");
                return FAILURE;
        }
        */


        /* sets the write socket to be a raw IP socket */
        int one = 1;
        int s = 1;
        /* ** declaring and configuring the read sfd here leads to problem **
        s = setsockopt(sfd_r, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        if (s < 0) {
                LOGX("setsockopt()");
                close(sfd_r);
                return FAILURE;
        }
        */
        s = setsockopt(sfd_w, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        if (s < 0) {
                LOGX("setsockopt()");
                PEACEOUT_W;
        }


        LOGV("prepared socket for write");

        
        LOGI("About to start experiment");
        LOGV("This program will send an OOB packet and wait");
        LOGV("for 3 second. Then, it sends a SYN packet, waits"); 
        LOGV("for 1 second, and sends an OOB packet again."); 
        LOGV("The receiver is expected to return a SYNACK");
        LOGV("five seconds after it receives the SYN. When this");
        LOGV("program sees the SYN-ACK, it sends the OOB again.");


        /* prepares OOB packet */
        char* oob_pkt = malloc(kPKT_MAX_LEN);
        if (oob_pkt == NULL) {
                LOGX("malloc()");
                PEACEOUT_W;
        }
        memset(oob_pkt, 0, kPKT_MAX_LEN);
        s = prepare_tcp_pkt(kPKT_TYPE_OOB,
                            &oob_pkt, src_port, dst_port, src_addr, dst_addr);
        if (s) {
                LOGX("prepare_tcp_pkt()");
                PEACEOUT_OW;
        }
        const size_t kOOB_PKT_LEN = kIP_HDR_LEN + kTCP_HDR_LEN
                                 + strlen(kPAYLOAD); /* now with data */

        LOGV("prepared first OOB packet");


        /* prepares SYN packet */
        char* syn_pkt = malloc(kPKT_MAX_LEN);
        if (syn_pkt == NULL) {
                LOGX("malloc()");
                PEACEOUT_OW;
        }
        memset(syn_pkt, 0, kPKT_MAX_LEN);
        s = prepare_tcp_pkt(kPKT_TYPE_SYN, 
                            &syn_pkt, src_port, dst_port, src_addr, dst_addr);
        if (s) {
                LOGX("prepare_tcp_pkt()");
                PEACEOUT_SOW;
        }
        const size_t kSYN_PKT_LEN = kIP_HDR_LEN + kTCP_HDR_LEN;

        LOGV("prepared SYN packet");
 

        /* sends first OOB packet */
        if (sendto(sfd_w, oob_pkt, kOOB_PKT_LEN , 0, 
                   (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                LOGX("sendto()");
                PEACEOUT_SOW;
        } else {
                LOGI("sent first OOB packet; next: SYN");
                sleep(3);
        }


        /* sends SYN */
        if (sendto(sfd_w, syn_pkt, kSYN_PKT_LEN, 0, 
                   (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                LOGX("sendto()");
                PEACEOUT_SOW;
        } else {
                LOGI("sent SYN; next: second OOB");
                FREE_PTR(syn_pkt);
                LOGV("cleaned up SYN packet");
                sleep(1);
        }


        /* prepares second OOB packet */
        memset(oob_pkt, 0, kPKT_MAX_LEN);
        s = prepare_tcp_pkt(kPKT_TYPE_OOB,
                            &oob_pkt, src_port, dst_port, src_addr, dst_addr);
        if (s) {
                LOGX("prepare_tcp_pkt()");
                PEACEOUT_OW;
        }

        LOGV("prepared second OOB packet");
 

        /* sends second OOB packet */
        if (sendto(sfd_w, oob_pkt, kOOB_PKT_LEN , 0, 
                   (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                LOGX("sendto()");
                PEACEOUT_OW;
        } else {
                LOGI("sent second OOB packet; waiting for SYNACK");
        }


        /**
         * waits for SYNACK sent from the server as recorded in dst_in; 
         * uses select() to know when it's ready
         */

        /* gets a second socket for read */
        int sfd_r = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sfd_r < 0) {
                LOGX("socket()");
                PEACEOUT_OW;
        }

        /* sets the read socket to be a raw IP socket */
        s = setsockopt(sfd_r, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        if (s < 0) {
                LOGX("setsockopt()");
                PEACEOUT_OWR;
        }

        /* assigns the read socket to src_port */
        s = bind(sfd_r, (struct sockaddr*) &src_in, sizeof(src_in));
        if (s < 0) {
                LOGX("bind()");
                PEACEOUT_OWR;
        }

        /* adds the read socket to an fd set for read */
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sfd_r, &readfds);

        LOGV("prepared socket for read");

        /* select() will wait for 10 seconds max */
        struct timeval timeout;
        timeout.tv_sec = kSELECT_TIMEOUT;
        timeout.tv_usec = 0;

        int n = -1;
        char msg[kBUFFER_MAX_LEN];
        bzero(msg, kBUFFER_MAX_LEN);

        int ready = select(sfd_r + 1, &readfds, NULL, NULL, &timeout);

        if (ready == -1) {
                LOGX("select()");
                PEACEOUT_OWR;
        } else if (ready) {
                LOGV("sfd_r is ready for read");
                socklen_t len = sizeof(dst_in);
                n = recvfrom(sfd_r, msg, kBUFFER_MAX_LEN, 0, 
                        (struct sockaddr*) &dst_in, &len);
        } else {
                LOGX("select() timed out");
                PEACEOUT_OWR;
        }
 
        if (n < 0) {
                LOGX("recvfrom()");
                PEACEOUT_OWR;
        } else {
                LOGI("Received %d bytes", n);
                LOGP("received_packet", (void*) msg, n);
        }
        
        /* some checking */
        if (n < kIP_HDR_LEN + kTCP_HDR_LEN) {
                LOGX("fatal: fewer bytes %d than needed for two headers!", n);
                PEACEOUT_OWR;
        }
        struct ip* ip_hdr = (struct ip*) msg;
        if (ip_hdr->ip_p != IPPROTO_TCP) {
                LOGX("fatal: not a TCP packet");
                PEACEOUT_OWR;
        }

        char incoming_src_addr[16];
        char incoming_dst_addr[16];
        memset(incoming_src_addr, 0, 16);
        memset(incoming_dst_addr, 0, 16);

        inet_ntop(AF_INET, &(ip_hdr->ip_src), incoming_src_addr, 16);
        inet_ntop(AF_INET, &(ip_hdr->ip_dst), incoming_dst_addr, 16);

        /* checks for SYNACK flags */
        struct tcphdr* tcp_hdr
                = (struct tcphdr*) (msg + sizeof(struct ip));

        LOGI("received a TCP packet from %s:%u to %s:%u", 
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
                    

        /* if incoming packet is SYNACK, respond with OOB */
        if (
#if defined(THIS_IS_OS_X) || defined(THIS_IS_CYGWIN)
            tcp_hdr->th_flags == (TH_SYN | TH_ACK)
#elif defined(THIS_IS_LINUX)
            tcp_hdr->syn == 1 && tcp_hdr->ack == 1
#else
  #error "Undetected OS. See include/os_detect.h"
#endif
           ) {
                LOGI("This is a SYNACK packet. Send OOB again.");
                sleep(1);

                /* prepares third OOB packet */
                memset(oob_pkt, 0, kPKT_MAX_LEN);
                s = prepare_tcp_pkt(kPKT_TYPE_OOB,
                            &oob_pkt, src_port, dst_port, src_addr, dst_addr);
                if (s) {
                        LOGX("prepare_tcp_pkt()");
                        PEACEOUT_OWR;
                }

                /* sends third OOB packet */
                if (sendto(sfd_w, oob_pkt, kOOB_PKT_LEN , 0, 
                           (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                        LOGX("sendto()");
                        PEACEOUT_OWR;
                } else {
                        LOGI("sent third OOB packet; client side finishes.");
                        LOGV("cleaned up OOB packet");
                        FREE_PTR(oob_pkt);
                }
        } else {
                LOGX("unexpected TCP flag");
                hexdump("received_packet", (void*) msg, n);
                PEACEOUT_OWR;
        }

        /* I know it's bad not to check return value of close() */
        LOGV("cleaning up");
        close(sfd_w);
        close(sfd_r);
        LOGV("both sockets closed. shutting down");
        return 0;
}
