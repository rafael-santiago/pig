/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_PKTSLICER_H
#define PIG_PKTSLICER_H 1

#include <stdlib.h>

//void set_pkt_field(const char *field, unsigned char *buf, size_t buf_size, const unsigned int value);

void *get_pkt_field(const char *field, const unsigned char *buf, const size_t buf_size, size_t *field_size);

#endif
