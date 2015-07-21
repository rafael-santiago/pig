/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_MKRND_H
#define PIG_MKRND_H 1

#include "types.h"

unsigned char mk_rnd_u1();

unsigned char mk_rnd_u3();

unsigned char mk_rnd_u4();

unsigned char mk_rnd_u6();

unsigned char mk_rnd_u8();

unsigned short mk_rnd_u13();

unsigned short mk_rnd_u16();

unsigned int mk_rnd_u32();

unsigned int mk_rnd_european_ipv4();

unsigned int mk_rnd_north_american_ipv4();

unsigned int mk_rnd_south_american_ipv4();

unsigned int mk_rnd_asian_ipv4();

unsigned int mk_rnd_ipv4_by_mask(const pig_target_addr_ctx *mask);

#endif
