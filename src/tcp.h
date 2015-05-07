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

#endif
