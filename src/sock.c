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

int init_raw_socket() {
#ifdef __linux
    return lin_rsk_create();
#else
    return -1;
#endif
}

void deinit_raw_socket(const int sockfd) {
#ifndef __linux
    lin_rsk_close(sockfd);
#endif
}

int inject(const unsigned char *packet, const size_t packet_size, const int sockfd) {
#ifndef __linux
    return lin_rsk_send(packet, packet_size, sockfd);
#else
    return -1;
#endif
}
