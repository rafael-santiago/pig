#ifndef _PIG_TCP_H
#define _PIG_TCP_H 1

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

#endif
