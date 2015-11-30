#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <errno.h>
#include <assert.h>

#include "os_detect.h"
#include "utility.h"
#include "constant.h"

#define FAILURE -1

/* usage: twhs_server [-p port] */
int 
main(int argc, char** argv)
{
        /* command line argument: port number to listen to */
        int local_port = kLISTEN_PORT_DEFAULT;
        parse_args_simple(argc, argv, &local_port);

        /* get a socket to play with */
        int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sd < 0) {
                fprintf(stderr, 
                        "socket() error: %s\n", strerror(errno));
                return FAILURE;
        }

        int s = 1;
        int one = 1;

        /* set the socket to be on raw IP level */
        s = setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        if (s < 0) {
                fprintf(stderr,
                        "setsockopt() error: %s\n", strerror(errno));
                return FAILURE;
        }

        /* bind the socket to local_port */
        struct sockaddr_in servaddr;
        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons((unsigned short) local_port);

        s = bind(sd, (struct sockaddr*) &servaddr, sizeof(servaddr));
        if (s < 0) {
                fprintf(stderr,
                        "bind() error: %s\n", strerror(errno));
                return FAILURE;
        }

        printf("Using port: %d\n", local_port);

        /* listen and respond */
        int n = -1;
        int i = 0;
        for (i = 0; i < 3; i++) {
                char msg[kBUFFER_MAX_LEN];
                bzero(msg, kBUFFER_MAX_LEN);
                //n = read(sd, msg, kBUFFER_MAX_LEN);
                // it seems sd won't be cleared after a read()
                n = recvfrom(sd, msg, kBUFFER_MAX_LEN, 0, NULL, NULL);
                if (n < 0) {
                        fprintf(stderr,
                                "recvfrom() error: %s\n", strerror(errno));
                        return FAILURE;
                }
                printf("Received %d bytes\n", n);
                //hexdump("received_packet", (void*) msg, n);

                /* integrity check */
                if (n < kIP_HDR_LEN + kTCP_HDR_LEN) {
                        fprintf(stderr,
                                "fatal: header length incomplete\n");
                        return FAILURE;
                }
                
                struct ip* ip_hdr = (struct ip*) msg;
                if ((ip_hdr->ip_hl != 5) || (ip_hdr->ip_v != 4)) {
                        fprintf(stderr,
                                "fatal: IP header corrupt\n");
                        return FAILURE;
                }
                if (ntohs(ip_hdr->ip_len) != n) {
                        fprintf(stderr,
                                "fatal: IP header indicates a different "
                                "byte count from read(): %d\n", 
                                ntohs(ip_hdr->ip_len));
                        return FAILURE;
                }
                if (ip_hdr->ip_p != IPPROTO_TCP) {
                        fprintf(stderr,
                                "fatal: IP header says it's not "
                                "a TCP packet\n");
                        return FAILURE;
                }
                char incoming_src_addr[16];
                char incoming_dst_addr[16];
                memset(incoming_src_addr, 0, 16);
                memset(incoming_dst_addr, 0, 16);

                inet_ntop(AF_INET, &(ip_hdr->ip_src), incoming_src_addr, 16);
                inet_ntop(AF_INET, &(ip_hdr->ip_dst), incoming_dst_addr, 16);

                printf("received IP packet from %s to %s\n", 
                       incoming_src_addr, incoming_dst_addr);

                struct tcphdr* tcp_hdr
                        = (struct tcphdr*) (msg + sizeof(struct ip));

                if (
#if defined(THIS_IS_OS_X) || defined(THIS_IS_CYGWIN)
                    tcp_hdr->th_flags == TH_SYN
#elif defined(THIS_IS_LINUX)
                    tcp_hdr->syn == 1
#else
  #error "Undetected OS. See include/os_detect.h"
#endif
                   ) {
                        printf("received a SYN packet. wait for 5 sec.\n");
                        sleep(5);
                        printf("send SYN ACK\n");


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
 
                        /* prepare address data structure */

                        struct sockaddr_in dst_in; 
                        dst_in.sin_family = AF_INET;
                        dst_in.sin_port = htons(dst_port);
                        dst_in.sin_addr.s_addr = inet_addr(incoming_src_addr);
                 
                        char* synack_pkt = malloc(kPKT_MAX_LEN);
                        memset(synack_pkt, 0, kPKT_MAX_LEN);

                        prepare_tcp_pkt(kPKT_TYPE_SYNACK, 
                                        &synack_pkt, 
                                        local_port, 
                                        dst_port, 
                                        incoming_dst_addr, 
                                        incoming_src_addr);

                        const size_t kSYNACK_PKT_LEN = kIP_HDR_LEN 
                                                     + kTCP_HDR_LEN;
                        /* SYNACK */

                        if (sendto(sd, synack_pkt, kSYNACK_PKT_LEN, 0, 
                                   (struct sockaddr*) &dst_in, sizeof(dst_in)) 
                            < 0) {
                                fprintf(stderr, 
                                        "sendto() error: %s\n", strerror(errno));
                        } else {
                                printf("\tSYNACK packet successfully sent\n");
                        }

                        free(synack_pkt);


                } else if ( 
#if defined(THIS_IS_OS_X) || defined(THIS_IS_CYGWIN)
                    ((tcp_hdr->th_flags & (TH_SYN | TH_ACK)) == 0)
#elif defined(THIS_IS_LINUX)
                    (tcp_hdr->syn == 0) && (tcp_hdr->ack == 0)
#else
  #error "Undetected OS. See include/os_detect.h"
#endif
                ) {
                        printf("received an OOB packet\n");
                        int payloadlen = n - kIP_HDR_LEN - kTCP_HDR_LEN;
                        printf("there should be %d payload bytes:\n",
                               payloadlen);
                        assert(payloadlen > 0);
                        int i;
                        for (i = 0; i < payloadlen; i++) {
                                printf("%c", 
                                       *(msg + sizeof(struct ip) 
                                         + sizeof(struct tcphdr) + i));
                        }
                        printf("\n");

                } else {
                        fprintf(stderr, "unrecognized TCP flag\n");
                }

        } // for (;;)







        return 0;
}

