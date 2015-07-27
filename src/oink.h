/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_OINK_H
#define PIG_OINK_H 1

#include "types.h"

int oink(const pigsty_entry_ctx *signature, pig_hwaddr_ctx **hwaddr, const pig_target_addr_ctx *addrs, const int sockfd, const unsigned char *gw_hwaddr, const char *loiface);

#endif
