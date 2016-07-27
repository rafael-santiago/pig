/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_UDP_H
#define PIG_UDP_H 1

#include <stdlib.h>

struct udp {
    unsigned short src;
    unsigned short dst;
    unsigned short len;
    unsigned short chsum;
    unsigned char *payload;
    size_t payload_size;
};

void parse_udp_dgram(struct udp **hdr, const unsigned char *buf, size_t bsize);

unsigned char *mk_udp_buffer(const struct udp *hdr, size_t *bsize);

unsigned short eval_udp_chsum(const struct udp hdr, const unsigned int src_addr,
                              const unsigned int dst_addr, unsigned short phdr_len);

void *get_udp_payload(const char *buf, const size_t buf_size, size_t *field_size);

#endif