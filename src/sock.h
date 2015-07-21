/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_SOCK_H
#define PIG_SOCK_H 1

#include <stdlib.h>

int init_raw_socket();

int inject(const unsigned char *packet, const size_t packet_size, const int sockfd);

void deinit_raw_socket(const int sockfd);

#endif
