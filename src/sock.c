/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "sock.h"
#ifdef __linux
#include "linux/rsk.h"
#endif

int init_raw_socket(const char *iface) {
#ifdef __linux
    return lin_rsk_create(iface);
#else
    return -1;
#endif
}

int init_loopback_raw_socket() {
#ifdef __linux
    return lin_rsk_lo_create();
#else
    return -1;
#endif
}

void deinit_raw_socket(const int sockfd) {
#ifdef __linux
    lin_rsk_close(sockfd);
#endif
}

int inject(const unsigned char *packet, const size_t packet_size, const int sockfd) {
#ifdef __linux
    return lin_rsk_sendto(packet, packet_size, sockfd);
#else
    return -1;
#endif
}

int inject_lo(const unsigned char *packet, const size_t packet_size, const int sockfd) {
#ifdef __linux
    return lin_rsk_lo_sendto(packet, packet_size, sockfd);
#else
    return -1;
#endif
}
