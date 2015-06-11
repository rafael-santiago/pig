/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _PIG_TO_IPV4_H
#define _PIG_TO_IPV4_H 1

unsigned int *to_ipv4(const char *data);

unsigned int *to_ipv4_mask(const char *mask);

unsigned int *to_ipv4_cidr(const char *range);

#endif
