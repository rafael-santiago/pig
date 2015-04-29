/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "memory.h"
#include <stdio.h>

void *pig_newseg(const size_t ssize) {
    void *seg = NULL;
    if (ssize == 0) {
        return NULL;
    }
    seg = malloc(ssize);
    if (seg == NULL) {
        printf("pig panic: no memory!\n");
        exit(1);
    }
    return seg;
}
