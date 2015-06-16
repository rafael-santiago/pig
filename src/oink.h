/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _PIG_OINK_H
#define _PIG_OINK_H 1

#include "types.h"

int oink(const pigsty_entry_ctx *signature, const pig_target_addr_ctx *addrs, const int sockfd);

#endif
