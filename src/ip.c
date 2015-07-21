/*                                                                                                                                                                                                                 
 *                                Copyright (C) 2015 by Rafael Santiago                                                                                                                                            
 *                                                                                                                                                                                                                 
 * This is a free software. You can redistribute it and/or modify under                                                                                                                                            
 * the terms of the GNU General Public License version 2.
 *
 */
#include "ip.h"
#include "memory.h"
#include <string.h>

void parse_ip4_dgram(struct ip4 **hdr, const unsigned char *buf, size_t bsize) {
    struct ip4 *ip = NULL;
    size_t payload_offset = 0, p = 0;
    if (hdr == NULL || *hdr == NULL || buf == NULL) {
        return;
    }
    ip = *hdr;
    if (bsize < 1) {
        return;
    }
    ip->version = (buf[0] & 0xf0) >> 4;
    ip->ihl = buf[0] & 0x0f;
    if (bsize < ip->ihl * 4) {
        memset(ip, 0, sizeof(struct ip4));
        return;
    }
    ip->tos = buf[1];
    ip->tlen = ((unsigned short)buf[2] << 8) | buf[3];
    ip->id = ((unsigned short)buf[4] << 8) | buf[5];
    ip->flags_fragoff = ((unsigned short)buf[6]) << 8 | buf[7];
    ip->ttl = buf[8];
    ip->protocol = buf[9];
    ip->chsum = ((unsigned short)buf[10] << 8) | buf[11];
    ip->src = ((unsigned int)buf[12] << 24) |
              ((unsigned int)buf[13] << 16) |
              ((unsigned int)buf[14] <<  8) | buf[15];
    ip->dst = ((unsigned int)buf[16] << 24) |
              ((unsigned int)buf[17] << 16) |
              ((unsigned int)buf[18] <<  8) | buf[19];
    payload_offset = (ip->ihl * 4);
    if (payload_offset < bsize) {
        ip->payload = (unsigned char *) pig_newseg(payload_offset + 1);
        ip->payload_size = bsize - payload_offset;
        for (p = 0; p < ip->payload_size; p++) {
            ip->payload[p] = buf[payload_offset + p];
        }
    } else {
        ip->payload = NULL;
        ip->payload_size = 0;
    }
}

unsigned char *mk_ip4_buffer(const struct ip4 *hdr, size_t *bsize) {
    unsigned char *retval = NULL;
    size_t p = 0;
    if (hdr == NULL || bsize == NULL) {
        return NULL;
    }
    *bsize = hdr->tlen;
    retval = (unsigned char *) pig_newseg(*bsize);
    retval[ 0] = (hdr->version << 4) | hdr->ihl;
    retval[ 1] = hdr->tos;
    retval[ 2] = (hdr->tlen & 0xff00) >> 8;
    retval[ 3] = (hdr->tlen & 0x00ff);
    retval[ 4] = (hdr->id & 0xff00) >> 8;
    retval[ 5] = (hdr->id & 0x00ff);
    retval[ 6] = (hdr->flags_fragoff & 0xff00) >> 8;
    retval[ 7] = (hdr->flags_fragoff & 0x00ff);
    retval[ 8] = hdr->ttl;
    retval[ 9] = hdr->protocol;
    retval[10] = (hdr->chsum & 0xff00) >> 8;
    retval[11] = (hdr->chsum & 0x00ff);
    retval[12] = (hdr->src & 0xff000000) >> 24;
    retval[13] = (hdr->src & 0x00ff0000) >> 16;
    retval[14] = (hdr->src & 0x0000ff00) >>  8;
    retval[15] = (hdr->src & 0x000000ff);
    retval[16] = (hdr->dst & 0xff000000) >> 24;
    retval[17] = (hdr->dst & 0x00ff0000) >> 16;
    retval[18] = (hdr->dst & 0x0000ff00) >>  8;
    retval[19] = (hdr->dst & 0x000000ff);
    if (*bsize > 20) {
        for (p = 0; p < hdr->payload_size; p++) {
            retval[20 + p] = hdr->payload[p];
        }
    }
    return retval;
}

unsigned short eval_ip4_chsum(const struct ip4 hdr) {
    int retval = 0;
    unsigned char hi = 0, lo = 0;
    size_t p = 0;
    retval += ((((unsigned short)((hdr.version << 4) | hdr.ihl)) << 8) | hdr.tos);
    retval += hdr.tlen;
    retval += hdr.id;
    retval += hdr.flags_fragoff;
    retval += ((unsigned short)(hdr.ttl << 8) | hdr.protocol);
    retval += hdr.chsum;
    retval += (hdr.src >> 16);
    retval += (hdr.src & 0x0000ffff);
    retval += (hdr.dst >> 16);
    retval += (hdr.dst & 0x0000ffff);
    if (hdr.payload_size > 0 && hdr.payload != NULL) {
        p = 0;
        while (p < hdr.payload_size) {
            hi = hdr.payload[p++];
            lo = 0;
            if (p < hdr.payload_size) {
                lo = hdr.payload[p++];
            }
            retval += ((unsigned short)(hi << 8) | lo);
        }
    }
    while (retval >> 16) {
        retval = (retval >> 16) + (retval & 0x0000ffff);
    }
    return (unsigned short)(~retval);
}
