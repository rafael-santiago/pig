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

static unsigned char *icmp_payload_parser(const unsigned char *buf, const size_t bsize, size_t *payload_size);

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
        icmp->payload = icmp_payload_parser(&buf[4], bsize - 4, &icmp->payload_size);
    } else {
        icmp->payload_size = 0;
        icmp->payload = NULL;
    }
}

unsigned char *mk_icmp_buffer(const struct icmp *hdr, size_t *bsize) {
    unsigned char *retval = NULL;
    size_t p = 0;
    retval = (unsigned char *) pig_newseg(hdr->payload_size + 4);
    retval[0] = hdr->type;
    retval[1] = hdr->code;
    retval[2] = (hdr->chsum >> 8);
    retval[3] = (hdr->chsum & 0x00ff);
    for (p = 0; p < hdr->payload_size; p++) {
        retval[4 + p] = hdr->payload[p];
    }
    return retval;
}

static unsigned char *icmp_payload_parser(const unsigned char *buf, const size_t bsize, size_t *payload_size) {
    unsigned char *payload = NULL;
    size_t b = 0;
    if (buf == NULL || bsize == 0 || payload_size == NULL) {
        return NULL;
    }
    payload = (unsigned char *) pig_newseg(bsize);
    memset(payload, 0, bsize);
    for (b = 0; b < bsize; b++) {
        payload[b] = buf[b];
    }
    *payload_size = bsize;
    return payload;
}

unsigned short eval_icmp_chsum(const struct icmp hdr) {
    int sum = 0;
    unsigned char hi = 0;
    unsigned char lo = 0;
    size_t p = 0;
    sum = (((unsigned short)hdr.type) << 8) | hdr.code;
    sum += hdr.chsum;
    if (hdr.payload != NULL) {
        for (p = 0; p < hdr.payload_size; p += 2) {
            hi = hdr.payload[p];
            lo = 0;
            if ((p + 1) < hdr.payload_size) {
                lo = hdr.payload[p + 1];
            }
            sum += ((unsigned short) hi << 8) | lo;
        }
    }
    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0x0000ffff);
    }
    return (unsigned short)(~sum);
}
