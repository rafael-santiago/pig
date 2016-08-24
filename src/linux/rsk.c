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
#include <linux/if_packet.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>

static int get_iface_index(const char *iface);

static int get_iface_index(const char *iface) {
    struct ifreq ifr;
    int sockfd;
    strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        return -1;
    }
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) != 0) {
        ifr.ifr_ifindex = -1;
    }
    close(sockfd);
    return ifr.ifr_ifindex;
}

int lin_rsk_create(const char *iface) {
    struct timeval tv;
    int yes = 1;
    int sk = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    setsockopt(sk, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes));
    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = 1;
    setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sk, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = get_iface_index(iface);
    if (bind(sk, (struct sockaddr *)&sll, sizeof(sll)) != 0) {
        lin_rsk_close(sk);
        return -1;
    }
    return sk;
}

int lin_rsk_lo_create() {
    int yes = 1;
    int sk = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sk != -1) {
        if (setsockopt(sk, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes)) == -1) {
            lin_rsk_close(sk);
            return -1;
        }
    }
    return sk;
}

void lin_rsk_close(const int sockfd) {
    close(sockfd);
}

int lin_rsk_sendto(const unsigned char *buffer, size_t buffer_size, const int sockfd) {
    return sendto(sockfd, buffer, buffer_size, 0, NULL, 0);
}

int lin_rsk_lo_sendto(const unsigned char *buffer, size_t buffer_size, const int sockfd) {
    struct sockaddr_in sk_in = { 0 };
    unsigned int ipv4_addr = 0;
    unsigned short dst_port = 0;
    size_t offset = 0;
    if (((buffer[0] & 0xf0) >> 4) != 4) {
        return -1;
    }
    if (buffer_size < 20) {  // WARN(Santiago): It must be at least a valid IP packet even if it brings an alien inside ;)
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
