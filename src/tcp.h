/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_TCP_H
#define PIG_TCP_H 1

#include <stdlib.h>

struct tcp {
    unsigned short src;
    unsigned short dst;
    unsigned int seqno;
    unsigned int ackno;
    unsigned char len;
    unsigned char reserv;
    unsigned char flags;
    unsigned short window;
    unsigned short chsum;
    unsigned short urgp;
    unsigned char *payload;
    size_t payload_size;
};

void parse_tcp_dgram(struct tcp **hdr, const unsigned char *buf, size_t bsize);

unsigned char *mk_tcp_buffer(const struct tcp *hdr, size_t *bsize);

unsigned short eval_tcp_ip4_chsum(const struct tcp hdr, const unsigned int src_addr, const unsigned int dst_addr);

void *get_tcp_payload(const unsigned char *buf, const size_t buf_size, size_t *field_size);

#endif
