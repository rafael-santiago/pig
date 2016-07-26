/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "to_int.h"
#include <stdlib.h>
#include <string.h>

unsigned int to_int(const char *value) {
    const char *vp = value;
    int retval = 0;
    if (vp == NULL) {
        return 0;
    }
    if (strlen(value) >= 3) {
        if (*vp == '0' && *(vp + 1) == 'x') {
            retval = strtoul(vp + 2, NULL, 16);
            return retval;
        }
    }
    retval = atoi(value);
    return retval;
}
