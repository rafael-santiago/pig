/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "rsk.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_ether.h>

int lin_rsk_create() {
    int sockfd = socket(AF_INET, SOCK_RAW, htons(ETH_P_ALL));
    int enabled = 1;
    if (sockfd != -1) {
        if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &enabled, sizeof(enabled)) == -1) {
            perror("setsockopt");
            lin_rsk_close(sockfd);
            return -1;
        }
    }
    return sockfd;
}

void lin_rsk_close(const int sockfd) {
    close(sockfd);
}

int lin_rsk_sendto(const char *buffer, size_t buffer_size, const int sockfd) {
    struct sockaddr_in sk_in = { 0 };
    unsigned int ipv4_addr = 0;
    if (((buffer[0] & 0xf0) >> 4) == 4) {
        return -1;
    }
    if (buffer_size < 20) { //  WARN(Santiago): It must be at least a valid IP packet even if it brings an alien inside ;)
        return -1;
    }
    ipv4_addr = (((unsigned short) buffer[12]) << 24) |
                (((unsigned short) buffer[13]) << 16) |
                (((unsigned short) buffer[14]) <<  8) |
                ((unsigned short) buffer[15]);
    sk_in.sin_family = AF_INET;
    sk_in.sin_addr.s_addr = htonl(ipv4_addr);
    return sendto(sockfd, buffer, buffer_size, 0, (struct sockaddr *)&sk_in, sizeof(sk_in));
}
