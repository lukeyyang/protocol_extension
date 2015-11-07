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

#define FAILURE -1

extern char* optarg;

const static size_t kIP_HDR_LEN = 20;
const static size_t kTCP_HDR_LEN = 20;
const static size_t kBUFFER_MAX_LEN = 256;
const static int kLISTEN_PORT_DEFAULT = 64001;

/* usage: twhs_server [-p port] */
int 
main(int argc, char** argv)
{
        /* command line argument: port number to listen to */
        int dst_port = kLISTEN_PORT_DEFAULT;
        int ch = -1;
        int num = 0;
        while ((ch = getopt(argc, argv, "p:")) != -1) {
                switch (ch) {
                case 'p':
                        num = (int) strtol(optarg, NULL, 10);
                        if ((!num) && (errno == EINVAL || errno == ERANGE)) {
                                fprintf(stderr,
                                        "Invalid port number to listen to, "
                                        "reset to default 64001\n");
                        } else {
                                dst_port = num;
                        }
                        break;
                case '?':
                default:
                        fprintf(stderr, 
                                "usage: %s [-p port_number_to_listen_to]\n",
                                argv[0]);
                        exit(-1);
                        break;
                }
        }

        int sd, n, clientfd;
        struct sockaddr_in servaddr, cliaddr;
        socklen_t len;

        sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sd < 0) {
                fprintf(stderr, 
                        "socket() error: %s\n", strerror(errno));
                return FAILURE;
        }

        int s = 1;
        int one = 1;
        s = setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
        if (s < 0) {
                fprintf(stderr,
                        "setsockopt() error: %s\n", strerror(errno));
                return FAILURE;
        }


        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons((unsigned short) dst_port);
        s = bind(sd, (struct sockaddr*) &servaddr, sizeof(servaddr));
        if (s < 0) {
                fprintf(stderr,
                        "bind() error: %s\n", strerror(errno));
                return FAILURE;
        }

        printf("Listening to localhost port: %d\n", dst_port);

        for (;;) {
                char msg[kBUFFER_MAX_LEN];
                bzero(msg, kBUFFER_MAX_LEN);
                n = read(sd, msg, kBUFFER_MAX_LEN);
                if (n < 0) {
                        fprintf(stderr,
                                "read() error: %s\n", strerror(errno));
                        return FAILURE;
                }
                printf("Received %d bytes\n", n);
                if (n < kIP_HDR_LEN) {
                        fprintf(stderr,
                                "fatal: received incomplete IP header\n");
                        return FAILURE;
                } else if (n < kIP_HDR_LEN + kTCP_HDR_LEN) {
                        fprintf(stderr,
                                "fatal: received incomplete IP and/or "
                                "TCP headers\n");
                        return FAILURE;
                }

                /* check it's TCP first */
                struct ip* ip_hdr = (struct ip*) msg;
                if ((ip_hdr->ip_hl != 5) || (ip_hdr->ip_v != 4)) {
                        fprintf(stderr,
                                "fatal: IP header corrupt\n");
                        return FAILURE;
                }
                if (ip_hdr->ip_len != n) {
                        fprintf(stderr,
                                "fatal: IP header indicates a different "
                                "byte count from read()\n");
                        return FAILURE;
                }
                if (ip_hdr->ip_p != IPPROTO_TCP) {
                        fprintf(stderr,
                                "fatal: IP header says it's not "
                                "a TCP packet\n");
                        return FAILURE;
                }
                char src_addr[16];
                char dst_addr[16];
                memset(src_addr, 0, 16);
                memset(dst_addr, 0, 16);

                s = inet_ntop(AF_INET, &(ip_hdr->ip_src), src_addr, 16);
                if (s != 1) {
                        fprintf(stderr, 
                                "inet_pton() error: %s\n", strerror(errno));
                        return;
                }
                s = inet_ntop(AF_INET, &(ip_hdr->ip_dst), dst_addr, 16);
                if (s != 1) {
                        fprintf(stderr, 
                                "inet_pton() error: %s\n", strerror(errno));
                        return;
                }
                printf("received IP packet from %s to %s\n", 
                       src_addr, dst_addr);

                struct tcphdr* = (struct tcphdr*) (msg + sizeof(struct ip));

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
                } else if ( /* note: below two logic are not strictly equal */
#if defined(THIS_IS_OS_X) || defined(THIS_IS_CYGWIN)
                    tcp_hdr->th_flags == 0 
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

        }







        /**
         * listen(): make this socket ready to accept connection requests
         *           allow 5 requests to queue up
         */
        s = listen(sd, 5);
        if (s < 0) {
                fprintf(stderr,
                        "listen() error: %s\n", strerror(errno));
                return FAILURE;
        }

        len = sizeof(cliaddr);

        while (1) {

                clientfd = accept(sd, (struct sockaddr*) &cliaddr, &len);
                if (clientfd < 0) {
                        fprintf(stderr,
                                "accept() error: %s\n", strerror(errno));
                        return FAILURE;
                }

                /*
                struct hostent *hostp;
                hostp = gethostbyaddr((const char*) &cliaddr.sin_addr.s_addr,
                    sizeof(cliaddr.sin_addr.s_addr), AF_INET);
                if (hostp == NULL) {
                        fprintf(stderr,
                                "gethostbyaddr() error: %s\n", 
                                strerror(errno));
                        return FAILURE;
                }
                */

                char* hostaddrp;
                hostaddrp = inet_ntoa(cliaddr.sin_addr);
                if (hostaddrp == NULL) {
                        fprintf(stderr,
                                "inet_ntoa() errorL %s\n", strerror(errno));
                        return FAILURE;
                }
                printf("established connection with %s\n",
                       hostaddrp);

                int i = 0;

                printf("\t%d\n", i++);
                printf("--------------------------------------------------\n");

                for (i = 0; i < n; i++)
                        printf("%c", *(msg + i));
                printf("\n");
                printf("Continue printing the receive buffer, "
                       "until a NULL byte is seen:\n");
                for (i = 0; 
                    (*(msg + n + i) != '\0' && n + i < kBUFFER_MAX_LEN); i++)
                        printf("0x%X, ", *(msg + n + i));
                printf("\n");
                printf("--------------------------------------------------\n");
        }
        return 0;
}

