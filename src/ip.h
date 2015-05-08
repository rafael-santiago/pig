#ifndef _PIG_IP_H
#define _PIG_IP_H 1

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

void parse_ip4_dgram(struct ip4 **hdr, const char *buf, size_t bsize);

unsigned char *mk_ip4_buffer(const struct ip4 *hdr, size_t *bsize);

#endif