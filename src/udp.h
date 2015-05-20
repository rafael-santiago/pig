#ifndef _PIG_UDP_H
#define _PIG_UDP_H 1

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

#endif