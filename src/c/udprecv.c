#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>

extern char* optarg;

#include "os_detect.h"
#include "constant.h"


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


        int sockfd, n;
        struct sockaddr_in servaddr, cliaddr;
        socklen_t len;
        char msg[kBUFFER_MAX_LEN];

        sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(dst_port);
        bind(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr));

        int i = 0;

        while (1) {
                /** IMPORTANT NOTE
                 *  WITHOUT the below line bzero(), complie with gcc 5.2.0, 
                 *  msg will end up containing more than n valid bytes, but 
                 *  compiling with clang won't lead to such problem
                 */
                bzero(msg, kBUFFER_MAX_LEN);
                len = sizeof(cliaddr);
                n = recvfrom(sockfd, msg, kBUFFER_MAX_LEN, 0, 
                    (struct sockaddr *) &cliaddr, &len);
                printf("\t%d\n", i++);
                printf("--------------------------------------------------\n");
                printf("Received %d UDP payload bytes:\n", n);
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
                printf("--------------------------------------------------\n");
        }
        return 0;
}
