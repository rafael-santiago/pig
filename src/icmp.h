/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_ICMP_H
#define PIG_ICMP_H 1

#include <stdlib.h>

struct icmp {
    unsigned char type;
    unsigned char code;
    unsigned short chsum;
    unsigned char *data;
    size_t dsize;
};

void parse_icmp_dgram(struct icmp **hdr, const unsigned char *buf, size_t bsize);

unsigned char *mk_icmp_buffer(const struct icmp *hdr, size_t *bsize);

unsigned short eval_icmp_chsum(const struct icmp hdr);

#endif
