/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_LINUX_RSK_H
#define PIG_LINUX_RSK_H 1

#include <stdlib.h>

int lin_rsk_create(const char *iface);

int lin_rsk_lo_create();

void lin_rsk_close(const int sockfd);

int lin_rsk_sendto(const unsigned char *buffer, size_t buffer_size, const int sockfd);

int lin_rsk_lo_sendto(const unsigned char *buffer, size_t buffer_size, const int sockfd);

#endif
