#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <strings.h>


#include "os_detect.h"

const static size_t kBUFFER_MAX_LEN = 1024;
const static int kDST_PORT = 64001;

int main()
{
        int sockfd, n;
        struct sockaddr_in servaddr, cliaddr;
        socklen_t len;
        char msg[kBUFFER_MAX_LEN];

        sockfd = socket(AF_INET, SOCK_DGRAM, 0);

        bzero(&servaddr, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port = htons(kDST_PORT);
        bind(sockfd, (struct sockaddr*) &servaddr, sizeof(servaddr));

        while (1) {
                len = sizeof(cliaddr);
                n = recvfrom(sockfd, msg, kBUFFER_MAX_LEN, 0, 
                    (struct sockaddr *) &cliaddr, &len);
                printf("-------------------------------------------------------\n");
                printf("Received %d bytes\n", n);
                printf("Dump of the first %d bytes: \n", n);
                int i;
                for (i = 0; i < n; i++)
                        printf("%c", *(msg + i));
                printf("\n");
                printf("Hexdump of the next two bytes: 0x%X 0x%X\n", 
                    *(msg + n), *(msg + n + 1));
                printf("-------------------------------------------------------\n");
        }
        return 0;
}

