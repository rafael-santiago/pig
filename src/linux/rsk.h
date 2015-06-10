/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _PIG_LINUX_RSK_H
#define _PIG_LINUX_RSK_H 1

#include <stdlib.h>

int lin_rsk_create();

void lin_rsk_close(const int sockfd);

int lin_rsk_sendto(const char *buffer, size_t buffer_size, const int sockfd);

#endif
