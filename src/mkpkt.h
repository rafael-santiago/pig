/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _PIG_MKPKT_H
#define _PIG_MKPKT_H 1

#include "types.h"
#include <stdlib.h>

unsigned char *mk_ip_pkt(pigsty_conf_set_ctx *conf, pig_target_addr_ctx *addrs, size_t *pktsize);

#endif
