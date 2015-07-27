/*
 *                        Copyright (C) 2014, 2015 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "arp.h"
#include "memory.h"
#include "eth.h"
#include "if.h"
#include "ip.h"
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <string.h>
#include <ctype.h>

#define getnibble(n) ( isxdigit(n) && isalpha(n) ? toupper(n) - 55 :\
                       isxdigit(n) && isdigit(n) ? n - 48 : n )

struct arp *parse_arp_dgram(const unsigned char *buf, const size_t bsize) {
    struct arp *arph = NULL;
    if (buf == NULL) {
        return NULL;
    }
    arph = (struct arp *) pig_newseg(sizeof(struct arp));
    memset(arph, 0, sizeof(struct arp));
    if (bsize == 0) {
        return NULL;
    }
    arph->hwtype = (unsigned short)(buf[0] << 8) | (unsigned short)(buf[1]);
    arph->ptype = (unsigned short)(buf[2] << 8) | (unsigned short)(buf[3]);
    arph->hw_addr_len = buf[4];
    arph->pt_addr_len = buf[5];
    arph->opcode = (unsigned short)(buf[6] << 8) | (unsigned short)(buf[7]);
    arph->src_hw_addr = (unsigned char *) pig_newseg(arph->hw_addr_len);
    memcpy(arph->src_hw_addr, &buf[8], arph->hw_addr_len);
    arph->src_pt_addr = (unsigned char *) pig_newseg(arph->pt_addr_len);
    memcpy(arph->src_pt_addr, &buf[8 + arph->hw_addr_len], arph->pt_addr_len);
    arph->dest_hw_addr = (unsigned char *) pig_newseg(arph->hw_addr_len);
    memcpy(arph->dest_hw_addr, &buf[8 + arph->hw_addr_len + arph->pt_addr_len], arph->hw_addr_len);
    arph->dest_pt_addr = (unsigned char *) pig_newseg(arph->pt_addr_len);
    memcpy(arph->dest_pt_addr, &buf[8 + arph->hw_addr_len + arph->hw_addr_len + arph->pt_addr_len], arph->pt_addr_len);
    return arph;
}

unsigned char *mk_arp_dgram(size_t *bsize, const struct arp arph) {
    unsigned char *dgram = NULL, *dp;
    size_t a;
    if (bsize == NULL || arph.src_hw_addr == NULL ||
                         arph.src_pt_addr == NULL ||
                        arph.dest_hw_addr == NULL ||
                        arph.dest_pt_addr == NULL) {
        return NULL;
    }
    dgram = (unsigned char *) pig_newseg(8 + (arph.hw_addr_len * 2) +
                                              (arph.pt_addr_len * 2));
    dp = dgram;
    *dp = (arph.hwtype >> 8);
    dp++;
    *dp = (arph.hwtype & 0x00ff);
    dp++;
    *dp = (arph.ptype >> 8);
    dp++;
    *dp = (arph.ptype & 0x00ff);
    dp++;
    *dp = arph.hw_addr_len;
    dp++;
    *dp = arph.pt_addr_len;
    dp++;
    *dp = (arph.opcode >> 8);
    dp++;
    *dp = (arph.opcode & 0x00ff);
    dp++;
    for (a = 0; a < arph.hw_addr_len; a++, dp++) {
        *dp = arph.src_hw_addr[a];
    }
    for (a = 0; a < arph.pt_addr_len; a++, dp++) {
        *dp = arph.src_pt_addr[a];
    }
    for (a = 0; a < arph.hw_addr_len; a++, dp++) {
        *dp = arph.dest_hw_addr[a];
    }
    for (a = 0; a < arph.pt_addr_len; a++, dp++) {
        *dp = arph.dest_pt_addr[a];
    }
    *bsize = dp - dgram;
    return dgram;
}

unsigned char *mac2byte(const char *mac, size_t len) {
    const char *m;
    unsigned char *retval = (unsigned char *) pig_newseg(len);
    unsigned char *r = retval, *rend = r + len;
    memset(retval, 0, len);
    for (m = mac; *m != 0; m++) {
        if (r == rend) {
            break;
        }
        if (*m == ':') {
            r++;
        }
        *r = ((*r) << 4) | getnibble(*m);
    }
    return retval;
}
