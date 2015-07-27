/*
 *                        Copyright (C) 2014, 2015 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "eth.h"
#include "memory.h"
#include "arp.h"
#include "ip.h"
#include <string.h>

struct ethernet_frame *parse_ethernet_frame(const unsigned char *buf, const size_t bsize) {
    const unsigned char *bp = buf;
    struct ethernet_frame *eth = NULL;
    if (buf == NULL) {
        return NULL;
    }
    eth = (struct ethernet_frame *) pig_newseg(sizeof(struct ethernet_frame));
    memset(eth, 0, sizeof(struct ethernet_frame));
    if (bsize < 14) {
        return NULL;
    }
    memcpy(eth->dest_hw_addr, bp, sizeof(eth->dest_hw_addr));
    bp += sizeof(eth->dest_hw_addr);
    memcpy(eth->src_hw_addr, bp, sizeof(eth->src_hw_addr));
    bp += sizeof(eth->src_hw_addr);
    eth->ether_type = ((unsigned short) (*bp) << 8) | (unsigned short) (*(bp + 1));
    bp += sizeof(eth->ether_type);
    eth->payload = (unsigned char *) pig_newseg(bsize - 14);
    memcpy(eth->payload, bp, bsize - 14);
    eth->payload_size = bsize - 14;
    return eth;
}

unsigned char *mk_ethernet_frame(size_t *bsize, struct ethernet_frame eth) {
    unsigned char *retval = NULL, *rp;
    if (bsize == NULL) {
        return NULL;
    }
    retval = (unsigned char *) pig_newseg(14 + eth.payload_size);
    rp = retval;
    memcpy(rp, eth.dest_hw_addr, 6);
    rp += sizeof(eth.dest_hw_addr);
    memcpy(rp, eth.src_hw_addr, 6);
    rp += sizeof(eth.src_hw_addr);
    *rp = (eth.ether_type & 0xff00) >> 8;
    *(rp+1) = eth.ether_type & 0xff;
    rp += sizeof(eth.ether_type);
    memcpy(rp, eth.payload, eth.payload_size);
    //  INFO(Santiago): forget about FCS... :)
    *bsize = (rp - retval) + eth.payload_size;
    return retval;
}
