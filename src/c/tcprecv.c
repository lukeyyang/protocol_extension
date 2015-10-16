#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <errno.h>

#include "os_detect.h"

#define FAILURE -1

extern char* optarg;
extern int optind;
extern int optopt;
extern int opterr;
extern int optreset;

const static size_t kBUFFER_MAX_LEN = 1024;
const static int kLISTEN_PORT_DEFAULT = 64001;

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
        printf("Listening to localhost port: %d\n", dst_port);


        int sd, n, clientfd;
        struct sockaddr_in servaddr, cliaddr;
        socklen_t len;
        char msg[kBUFFER_MAX_LEN];

        sd = socket(AF_INET, SOCK_STREAM, 0);
        if (sd < 0) {
                fprintf(stderr, 
                        "socket() error: %s\n", strerror(errno));
                return FAILURE;
        }

        int one = 1;
        int s = 1;
        s = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
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

                struct hostent *hostp;
                hostp = gethostbyaddr((const char*) &cliaddr.sin_addr.s_addr,
                    sizeof(cliaddr.sin_addr.s_addr), AF_INET);
                if (hostp == NULL) {
                        fprintf(stderr,
                                "gethostbyaddr() error: %s\n", 
                                strerror(errno));
                        return FAILURE;
                }

                char* hostaddrp;
                hostaddrp = inet_ntoa(cliaddr.sin_addr);
                if (hostaddrp == NULL) {
                        fprintf(stderr,
                                "inet_ntoa() errorL %s\n", strerror(errno));
                        return FAILURE;
                }
                printf("established connection with %s (%s)\n",
                       hostp->h_name,
                       hostaddrp);



                int i = 0;

                printf("\t%d\n", i++);
                printf("--------------------------------------------------\n");
                bzero(msg, kBUFFER_MAX_LEN);
                n = read(clientfd, msg, kBUFFER_MAX_LEN);
                if (n < 0) {
                        fprintf(stderr,
                                "read() error: %s\n", strerror(errno));
                        return FAILURE;
                }
                printf("Received %d UDP payload bytes:\n", n);
                /*
                int i;
                for (i = 0; i < n; i++)
                        printf("%c", *(msg + i));
                printf("\n");
                printf("Continue printing the receive buffer, "
                       "until a NULL byte is seen:\n");
                for (i = 0; 
                    (*(msg + n + i) != '\0' && n + i < kBUFFER_MAX_LEN); i++)
                        printf("0x%X, ", *(msg + n + i));
                printf("\n");
                */
                printf("--------------------------------------------------\n");
        }
        return 0;
}
