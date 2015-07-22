/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "icmp.h"
#include "memory.h"
#include <string.h>

struct icmp_data_parser_calltable {
    unsigned char type;
    unsigned char *(*parse)(const unsigned char *buf, const size_t bsize, size_t *dsize);
};

static unsigned char *icmp_data_parser(const unsigned char *buf, const size_t bsize, size_t *dsize);

void parse_icmp_dgram(struct icmp **hdr, const unsigned char *buf, size_t bsize) {
    struct icmp *icmp = NULL;
    if (hdr == NULL || buf == NULL || bsize < 32) {
        return;
    }
    icmp = *hdr;
    icmp->type = buf[0];
    icmp->code = buf[1];
    icmp->chsum = (((unsigned short) buf[2]) << 8) | buf[3];
    if (bsize - 4 > 0) {
        icmp->data = icmp_data_parser(&buf[4], bsize - 4, &icmp->dsize);
    } else {
        icmp->dsize = 0;
        icmp->data = NULL;
    }
}

unsigned char *mk_icmp_buffer(const struct icmp *hdr, size_t *bsize) {
    unsigned char *retval = NULL;
    size_t d = 0;
    retval = (unsigned char *) pig_newseg(hdr->dsize + 4);
    retval[0] = hdr->type;
    retval[1] = hdr->code;
    retval[2] = (hdr->chsum >> 8);
    retval[3] = (hdr->chsum & 0x00ff);
    for (d = 0; d < hdr->dsize; d++) {
        retval[4 + d] = hdr->data[d];
    }
    return retval;
}

static unsigned char *icmp_data_parser(const unsigned char *buf, const size_t bsize, size_t *dsize) {
    unsigned char *data = NULL;
    size_t b = 0;
    if (buf == NULL || bsize == 0 || dsize == NULL) {
        return NULL;
    }
    data = (unsigned char *) pig_newseg(bsize);
    memset(data, 0, bsize);
    for (b = 0; b < bsize; b++) {
        data[b] = buf[b];
    }
    *dsize = bsize;
    return data;
}

unsigned short eval_icmp_chsum(const struct icmp hdr) {
    int sum = 0;
    unsigned char hi = 0;
    unsigned char lo = 0;
    size_t d = 0;
    sum = (((unsigned short)hdr.type) << 8) | hdr.code;
    sum += hdr.chsum;
    if (hdr.data != NULL) {
        for (d = 0; d < hdr.dsize; d += 2) {
            hi = hdr.data[d];
            lo = 0;
            if ((d+1) < hdr.dsize) {
                lo = hdr.data[d + 1];
            }
            sum += ((unsigned short) hi << 8) | lo;
        }
    }
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0x0000ffff);
    }
    return (unsigned short)(~sum);
}
