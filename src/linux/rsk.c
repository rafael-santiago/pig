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
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
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
    unsigned short dst_port = 0;
    size_t offset = 0;
    if (((buffer[0] & 0xf0) >> 4) != 4) {
        return -1;
    }
    if (buffer_size < 20) { //  WARN(Santiago): It must be at least a valid IP packet even if it brings an alien inside ;)
        return -1;
    }
    ipv4_addr = (((unsigned short) buffer[16]) << 24) |
                (((unsigned short) buffer[17]) << 16) |
                (((unsigned short) buffer[18]) <<  8) |
                ((unsigned short) buffer[19]);
    offset = 4 * (buffer[0] & 0x0f);
    switch (buffer[9]) {
        case  6:
        case 17:
            dst_port = (((unsigned short)buffer[offset + 2]) << 8) | buffer[offset + 3];
            break;

        default:
            dst_port = 0;
            break;
    }
    sk_in.sin_family = AF_INET;
    sk_in.sin_addr.s_addr = htonl(ipv4_addr);
    sk_in.sin_port = htons(dst_port);
    return sendto(sockfd, buffer, buffer_size, 0, (struct sockaddr *)&sk_in, sizeof(sk_in));
}
