/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "mkrnd.h"
#include <stdlib.h>

static unsigned int mk_rnd_ipv4(const int msb_floor);

unsigned char mk_rnd_u1() {
    return (rand() & 0x1);
}

unsigned char mk_rnd_u3() {
    return (rand() & 0x7);
}

unsigned char mk_rnd_u4() {
    return (rand() & 0xf);
}

unsigned char mk_rnd_u6() {
    return (rand() & 0x3f);
}

unsigned char mk_rnd_u8() {
    return (rand() & 0xff);
}

unsigned short mk_rnd_u13() {
    return (rand() & 0x1fff);
}

unsigned short mk_rnd_u16() {
    return (rand() & 0xffff);
}

unsigned int mk_rnd_u32() {
    return (rand() & 0xffffffff);
}

static unsigned int mk_rnd_ipv4(const int msb_floor) {
    unsigned char b0 = msb_floor + (rand() % 2);
    unsigned char b1 = 1 + (rand() % 254);
    unsigned char b2 = 1 + (rand() % 254);
    unsigned char b3 = 1 + (rand() % 254);
    return ((unsigned int) b0 << 24) |
           ((unsigned int) b1 << 16) |
           ((unsigned int) b2 <<  8) |
           ((unsigned int) b3);
}

unsigned int mk_rnd_european_ipv4() {
    return mk_rnd_ipv4(194);
}

unsigned int mk_rnd_north_american_ipv4() {
    return mk_rnd_ipv4(198);
}

unsigned int mk_rnd_south_american_ipv4() {
    return mk_rnd_ipv4(200);
}

unsigned int mk_rnd_asian_ipv4() {
    return mk_rnd_ipv4(202);
}

unsigned int mk_rnd_ipv4_by_mask(const pig_target_addr_ctx *mask) {
    unsigned int retval = 0;
    unsigned int rnd = 0;
    unsigned int maskval = 0;
    if (mask == NULL || mask->addr == NULL) {
        return 0;
    }

    switch (mask->type) {

        case kWild:
            maskval = *(unsigned int *)mask->addr;
            rnd = rand() % 0xffffff;
            retval = maskval;
            if ((maskval & 0xff000000) == 0xff000000) {
                retval = (rnd & 0xff000000) | (retval & 0x00ffffff);
            }
            if ((maskval & 0x00ff0000) == 0x00ff0000) {
                retval = (rnd & 0x00ff0000) | (retval & 0xff00ffff);
            }
            if ((maskval & 0x0000ff00) == 0x0000ff00) {
                retval = (rnd & 0x0000ff00) | (retval & 0xffff00ff);
            }
            if ((maskval & 0x000000ff) == 0xff) {
                retval = (rnd & 0x000000ff) | (retval & 0xffffff00);
            }
            break;

        case kAddr:
            retval = *(unsigned int *)mask->addr;
            break;

        case kCidr:
            maskval = 0xffffffff;
            maskval = maskval >> mask->cidr_range;
            retval = 0xffffffff ^ (rand() % maskval);
            maskval = *(unsigned int *)mask->addr;
            retval = maskval & retval;
            break;
    }

    return retval;
}
