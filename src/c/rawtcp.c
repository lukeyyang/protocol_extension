/**
 * rawtcp.c
 * client code for sending a TCP OOB packet before and after a TCP connection
 * usage: 
 *   rawtcp [-h src_addr] [-f src_port] [-d dst_addr] [-p dst_port] [-v]
 * requires root privilege
 *
 * sends TCP OOB packet using raw TCP sockets
 * establishes TCP connection using a separate TCP socket
 * works in pair with tcprecv
 */

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
#include "debug.h"

#define FAILURE -1


void print_info()
{
        LOGV("ARGS: [-h src_addr] [-f src_port] "
               "[-d dst_addr] [-p dst_port] [-v]\n"
               "*IMPORTANT*: source address (-h) is by default 127.0.0.1;\n"
               "  unless you are receiving from localhost, you SHOULD change\n"
               "  it to your real IP address\n"
               "*IMPORTANT*: DO NOT re-use the same sending port within about\n"
               "  three minutes\n");
}

int
main(int argc, char** argv)
{
        /* COMMAND LINE PARSING */

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

        /* Print out some useful information */
        print_info();


        printf("src: %s: %d\n", src_addr, src_port);
        printf("dst: %s: %d\n", dst_addr, dst_port);

        /* SET UP TWO SOCKETS */
        int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (sd < 0) {
                fprintf(stderr, 
                        "sd = socket() error: %s\n", strerror(errno));
                return FAILURE;
        }
        int sd_normal = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sd_normal < 0) {
                fprintf(stderr, 
                        "sd_normal = socket() error: %s\n", strerror(errno));
                return FAILURE;
        }


        /* sd for raw tcp, sd_normal for normal tcp */

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

        /* address data structure */

        struct sockaddr_in src_in, dst_in; 

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

        /* prepare packet */

        char* oob_pkt = malloc(kPKT_MAX_LEN);
        memset(oob_pkt, 0, kPKT_MAX_LEN);

        prepare_tcp_pkt(kPKT_TYPE_OOB,
                        &oob_pkt, src_port, dst_port, src_addr, dst_addr);

        const size_t kOOB_PKT_LEN = kIP_HDR_LEN + kTCP_HDR_LEN
                                 + strlen(kPAYLOAD); /* now with data */


        
        printf("About to send\n");
        printf("This program will attempt to send our special packet 3\n"
               "times, establish a TCP connection on the same socket,\n"
               "send out a test message in a normal way, pause for 5\n"
               "seconds, and send our special again for 3 times.\n");

        /* initial attempt to send the special packet */

        int i;
        for (i = 0; i < 3; i++) {
                if (sendto(sd, oob_pkt, kOOB_PKT_LEN, 0, 
                    (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                        fprintf(stderr, "sendto() error: %s\n", strerror(errno));
                        free(oob_pkt);
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
                if (sendto(sd, oob_pkt, kOOB_PKT_LEN, 0, 
                    (struct sockaddr*) &dst_in, sizeof(dst_in)) < 0) {
                        fprintf(stderr, "sendto() error: %s\n", strerror(errno));
                        free(oob_pkt);
                        close(sd);
                        return FAILURE;
                } else {
                        printf("%d - second group of special packet attempt"
                               " - sendto() OK.\n", i);
                        sleep(1);
                }
        }

        free(oob_pkt);
        close(sd_normal);
        close(sd);
        return 0;
}
