/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "endianess.h"

int little_endian() {
    unsigned char *m = "\x00\x00\x00\x01";
    return (*((unsigned int *)(m)) >> 24);
}
