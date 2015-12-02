/**
 * twhs_server.c
 * server code for receiving TCP OOB packet before and during a TCP connection
 * usage: twhs_server [-p portno] [-v]
 * requires root privilege
 *
 * uses raw IP sockets
 * prints out TCP payload if an OOB packet is received
 * rests for 5 seconds after receiving a SYN, then responds with SYNACK
 * in the current experiment, this server receives this sequence of packets:
 *   OOB    SYN    OOB    OOB
 * works in pair with twhs_client
 */

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <netdb.h>
#include <arpa/inet.h>

#include "os_detect.h"
#include "utility.h"
#include "constant.h"
#include "debug.h"

#define FAILURE -1

#define PEACEOUT_R { \
                close(sfd_r); \
                LOGV("closed sfd_r. shutting down"); \
                return FAILURE; \
}
#define PEACEOUT_WR { \
                close(sfd_w); \
                LOGV("closed sfd_w"); \
                PEACEOUT_R; \
}
#define PEACEOUT_SWR { \
                FREE_PTR(synack_pkt); \
                LOGV("cleaned up SYNACK packet"); \
                PEACEOUT_WR; \
}

int 
main(int argc, char** argv)
{
        /* command line argument: port number to listen to */
        int local_port = kLISTEN_PORT_DEFAULT;
        parse_args_simple(argc, argv, &local_port, &verbose);
        LOGI("server running on port %d", local_port);


        /* prepares server address data structure */
        struct sockaddr_in servaddr;
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons((unsigned short) local_port);
        LOGV("prepared server address data structure");

        /* gets a socket for reading */
        int sfd_r = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sfd_r < 0) {
                LOGX("socket()");
                return FAILURE;
        }

        int s = 1;
        int one = 1;

        /* set the socket to be on raw IP level */
        s = setsockopt(sfd_r, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        if (s < 0) {
                LOGX("setsockopt()");
                PEACEOUT_R;
        }

        /* bind the socket to local_port */
        s = bind(sfd_r, (struct sockaddr*) &servaddr, sizeof(servaddr));
        if (s < 0) {
                LOGX("bind()");
                PEACEOUT_R;
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

        /* dummy address for the client */
        struct sockaddr_in cli_addr;
        int client_known = 0;
        bzero(&cli_addr, sizeof(cli_addr));
        cli_addr.sin_family = AF_INET;

        LOGV("start listening to port %d", local_port);


        /* listen and respond */
        int n = -1;
        int i = 0;
        for (i = 0; i < 4;) {
                char msg[kBUFFER_MAX_LEN];
                bzero(msg, kBUFFER_MAX_LEN);
                /**
                 * there is a problem: the 4th and last incoming packet is
                 * supposed to be an OOB packet
                 * (the client sends an OOB before and after sending SYN, and 
                 * after receiving SYNACK: OOB - SYN - OOB - (SYNACK) - OOB),
                 * but the server finds it to be a SYN
                 */
                int ready = select(sfd_r + 1, &readfds, NULL, NULL, &timeout);

                if (ready == -1) {
                        LOGX("select()");
                        PEACEOUT_R;
                } else if (ready) {
                        LOGV("sfd_r is ready for read");
                } else {
                        LOGX("select() timed out");
                        PEACEOUT_R;
                }

                if (client_known) {
                        socklen_t len = sizeof(cli_addr);
                        n = recvfrom(sfd_r, msg, kBUFFER_MAX_LEN, 0, 
                                        (struct sockaddr*) &cli_addr, &len);
                } else {
                        n = read(sfd_r, msg, kBUFFER_MAX_LEN);
                }
                if (n < 0) {
                        if (client_known) {
                                LOGX("recvfrom()");
                        } else {
                                LOGX("read()");
                        }
                        PEACEOUT_R;
                }
                LOGI("**** Packet %d coming in ****", i);
                LOGI("Received %d bytes", n);
                LOGP("received_packet", (void*) msg, n);

                /* some checking  */
                if (n < kIP_HDR_LEN + kTCP_HDR_LEN) {
                        LOGX("fatal: fewer bytes %d "
                             "than needed for two headers!", n);
                        continue;
                }
                struct ip* ip_hdr = (struct ip*) msg;
                if (ip_hdr->ip_p != IPPROTO_TCP) {
                        LOGX( "fatal: not a TCP packet");
                        continue;
                }
                char incoming_src_addr[16];
                char incoming_dst_addr[16];
                memset(incoming_src_addr, 0, 16);
                memset(incoming_dst_addr, 0, 16);

                inet_ntop(AF_INET, &(ip_hdr->ip_src), incoming_src_addr, 16);
                inet_ntop(AF_INET, &(ip_hdr->ip_dst), incoming_dst_addr, 16);

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
 

                /* if incoming packet is SYN, respond with ACK */
                if (
#if defined(THIS_IS_OS_X) || defined(THIS_IS_CYGWIN)
                    tcp_hdr->th_flags == TH_SYN
#elif defined(THIS_IS_LINUX)
                    tcp_hdr->syn == 1 && tcp_hdr->ack == 0
#else
  #error "Undetected OS. See include/os_detect.h"
#endif
                   ) {
                        LOGI("received a SYN packet. wait for 5 sec.");
                        sleep(5);
                        LOGI("about to send SYNACK");


                        /* from which port, to which port */
                        int dst_port = ntohs(
#if defined(THIS_IS_OS_X) || defined(THIS_IS_CYGWIN)
                                             tcp_hdr->th_sport
#elif defined(THIS_IS_LINUX)
                                             tcp_hdr->source
#else
  #error "Undetected OS. See include/os_detect.h"
#endif
                                       );
 
                        /* prepares address data structure */

                        struct sockaddr_in dst_in; 
                        dst_in.sin_family = AF_INET;
                        dst_in.sin_port = htons(dst_port);
                        dst_in.sin_addr.s_addr = inet_addr(incoming_src_addr);
                 

                        /* gets a socket to write to */
                        int sfd_w = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
                        if (sfd_w < 0) {
                                LOGX("socket()");
                                PEACEOUT_R;
                        }

                        /* sets the write socket to be a raw IP socket */
                        s = setsockopt(sfd_w, IPPROTO_IP, IP_HDRINCL, 
                                        &one, sizeof(one));
                        if (s < 0) {
                                LOGX("setsockopt()");
                                PEACEOUT_WR;
                        }

                        LOGV("prepared socket for write");


                        /* prepares the SYNACK packet */
                        char* synack_pkt = malloc(kPKT_MAX_LEN);
                        if (synack_pkt == NULL) {
                                LOGX("malloc()");
                                PEACEOUT_WR;
                        }
                        memset(synack_pkt, 0, kPKT_MAX_LEN);

                        s = prepare_tcp_pkt(kPKT_TYPE_SYNACK, 
                                            &synack_pkt, 
                                            local_port, 
                                            dst_port, 
                                            incoming_dst_addr, 
                                            incoming_src_addr);
                        if (s) {
                                LOGX("prepare_tcp_pkt()");
                                PEACEOUT_SWR;
                        }

                        const size_t kSYNACK_PKT_LEN = kIP_HDR_LEN 
                                                     + kTCP_HDR_LEN;
                        LOGV("prepared SYNACK packet");


                        /* send SYNACK */

                        if (sendto(sfd_w, synack_pkt, 
                                   kSYNACK_PKT_LEN, 0, 
                                   (struct sockaddr*) &dst_in, 
                                   sizeof(dst_in)) < 0) {
                                LOGX("sendto()");
                                PEACEOUT_SWR;
                        } else {
                                LOGI("sent SYNACK packet");
                                LOGV("from %s:%d to %s:%d",
                                       incoming_dst_addr,
                                       local_port,
                                       incoming_src_addr,
                                       dst_port);
                        }

                        FREE_PTR(synack_pkt);
                        LOGV("cleaned up SYNACK packet");
                        close(sfd_w);
                        LOGV("closed sfd_w");

                        /* make this client known */

                        if (!client_known) {
                                client_known = 1;
                                cli_addr.sin_port = htons(dst_port);
                                cli_addr.sin_addr.s_addr =
                                        inet_addr(incoming_src_addr);
                        }
                        LOGV("marked client as known");


                } else if ( 
#if defined(THIS_IS_OS_X) || defined(THIS_IS_CYGWIN)
                    ((tcp_hdr->th_flags & (TH_SYN | TH_ACK)) == 0)
#elif defined(THIS_IS_LINUX)
                    (tcp_hdr->syn == 0) && (tcp_hdr->ack == 0)
#else
  #error "Undetected OS. See include/os_detect.h"
#endif
                ) {
                        LOGI("this is an OOB packet");
                        int payloadlen = n - kIP_HDR_LEN - kTCP_HDR_LEN;
                        LOGI("there should be %d payload bytes:",
                               payloadlen);
                        int j;
                        for (j = 0; j < payloadlen; j++) {
                                printf("%c", 
                                       *(msg + sizeof(struct ip) 
                                         + sizeof(struct tcphdr) + j));
                        }
                        printf("\n");


                } else {
                        LOGX("unexpected TCP flag");
                        if (
#if defined(THIS_IS_OS_X) || defined(THIS_IS_CYGWIN)
                            tcp_hdr->th_flags == (TH_SYN | TH_ACK)
#elif defined(THIS_IS_LINUX)
                            tcp_hdr->syn == 1 && tcp_hdr->ack == 1
#else
  #error "Undetected OS. See include/os_detect.h"
#endif
                           ) {
                               LOGW("This is a SYNACK packet.");
                        }
                        hexdump("[ERROR] received_packet", (void*) msg, n);
                }

                LOGI("**** end of packet %d ****", i++);

        } // for (i = 0; i < 4; )


        LOGV("cleaning up");
        close(sfd_r);
        LOGV("closed sfd_r. shutting down");
        return 0;
}
