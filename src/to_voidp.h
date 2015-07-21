/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_TO_VOIDP_H
#define PIG_TO_VOIDP_H 1

#include <stdlib.h>

void *int_to_voidp(const char *data, size_t *dsize);

void *str_to_voidp(const char *data, size_t *dsize);

void *ipv4_to_voidp(const char *data, size_t *dsize);

#endif
