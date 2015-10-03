#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include "utility.h"

#define kUSAGE "usage: %s [-h source_addr]"\
                         "[-f source_port]"\
                         "[-d dest_addr]"\
                         "[-p dest_port]\n"

void 
parse_args(int argc,
           char* const argv[],
           const char* source_addr,
           int* const source_port,
           const char* dest_addr,
           int* const dest_port)
{
        const static char* usage = kUSAGE;
        int ch = -1;
        int num = 0;
        while ((ch = getopt(argc, argv, "h:f:d:p:")) != -1) {
                switch (ch) {
                case 'h':
                        source_addr = optarg;
                        break;
                case 'f':
                        num = (int) strtol(optarg, NULL, 10);
                        if ((!num) && (errno == EINVAL || errno == ERANGE)) {
                                fprintf(stderr,
                                        "Invalid source port number, "
                                        "reset to default 64000\n");
                        } else {
                                *source_port = num;
                        }
                        break;
                case 'd':
                        dest_addr = optarg;
                        break;
                case 'p':
                        num = (int) strtol(optarg, NULL, 10);
                        if ((!num) && (errno == EINVAL || errno == ERANGE)) {
                                fprintf(stderr,
                                        "Invalid destination port number, "
                                        "reset to default 64001\n");
                        } else {
                                *dest_port = num;
                        }
                        break;
                case '?':
                default:
                        fprintf(stderr, usage, argv[0]);
                        exit(-1);
                        break;
                }
        }
        printf("Source address: %s\n", source_addr);
        printf("Source port: %d\n", *source_port);
        printf("Destination address: %s\n", dest_addr);
        printf("Destination port: %d\n", *dest_port);
}


uint16_t 
udp_checksum(uint16_t* buffer, int nwords)
{
        uint64_t sum;
        for (sum = 0; nwords > 0; nwords--) {
                sum += *buffer;
                buffer++;
        }
        sum = (sum >> 16) + (sum & 0xffff);
        sum += sum >> 16;
        return (uint16_t)(~sum);
}


