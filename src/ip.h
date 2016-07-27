/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_IP_H
#define PIG_IP_H 1

#include <stdlib.h>

struct ip4 {
    unsigned char version;
    unsigned char ihl;
    unsigned char tos;
    unsigned short tlen;
    unsigned short id;
    unsigned short flags_fragoff;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short chsum;
    unsigned int src;
    unsigned int dst;
    unsigned char *payload;
    size_t payload_size;
};

void parse_ip4_dgram(struct ip4 **hdr, const unsigned char *buf, size_t bsize);

unsigned char *mk_ip4_buffer(const struct ip4 *hdr, size_t *bsize);

unsigned short eval_ip4_chsum(const struct ip4 hdr);

unsigned char *addr2byte(const char *addr, size_t len);

void *get_ip4_payload(const char *buf, const size_t bsize, size_t *field_size);

#endif