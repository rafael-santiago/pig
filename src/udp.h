#ifndef _PIG_UDP_H
#define _PIG_UDP_H 1

struct udp {
    unsigned short src;
    unsigned short dst;
    unsigned short len;
    unsigned short chksum;
    unsigned char *payload;
    size_t payload_size;
};

#endif