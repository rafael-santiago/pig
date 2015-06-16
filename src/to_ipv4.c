/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "to_ipv4.h"
#include "memory.h"
#include <string.h>

unsigned int *to_ipv4(const char *data) {
    unsigned int *retval = NULL;
    const char *dp = NULL;
    char oct[20];
    size_t o = 0;
    if (data == NULL) {
        return NULL;
    }
    retval = (unsigned int *) pig_newseg(sizeof(unsigned  int));
    *retval = 0;
    memset(oct, 0, sizeof(oct));
    for (dp = data; *dp != 0; dp++) {
        if (*dp == '.' || *(dp + 1) == 0) {
            if (*(dp + 1) == 0) {
                oct[o] = *dp;
            }
            *retval = ((*retval) << 8) | atoi(oct);
            o = 0;
            memset(oct, 0, sizeof(oct));
        } else {
            oct[o] = *dp;
            o = (o + 1) % sizeof(oct);
        }
    }
    return retval;
}

unsigned int *to_ipv4_mask(const char *mask) {
    unsigned int *retval = NULL;
    const char *mp = NULL;
    char temp[20];
    unsigned char byte = 0;
    size_t t = 0;
    retval = (unsigned int *) pig_newseg(sizeof(unsigned int));
    if (strcmp(mask, "*") == 0) {
        *retval = 0xffffffff;
        return retval;
    }
    *retval = 0;
    memset(temp, 0, sizeof(temp));
    for (mp = mask; *mp != 0; mp++) {
        if (*mp == '.' || *(mp + 1) == 0) {
            if (*(mp + 1) == 0) {
                temp[t] = *mp;
            }
            byte = 0xff;
            if (strcmp(temp, "*") != 0) {
                byte = atoi(temp);
            }
            t = 0;
            memset(temp, 0, sizeof(temp));
            *retval = ((*retval) << 8) | byte;
        } else {
            temp[t] = *mp;
            t = (t + 1) % sizeof(temp);
        }
    }
    return retval;
}

unsigned int *to_ipv4_cidr(const char *range, unsigned int *cidr_range) {
    char temp[0xff];
    char *tp = NULL;
    unsigned int *ip = NULL;
    unsigned int mask = 0xffffffff;
    memset(temp, 0, sizeof(temp));
    strncpy(temp, range, sizeof(temp) - 1);
    tp = strstr(temp, "/");
    if (tp == NULL) {
        return NULL;
    }
    *tp = 0;
    ip = to_ipv4(temp);
    if (ip == NULL) {
        return NULL;
    }
    tp = strstr(range, "/");
    if (tp == NULL) {
        free(ip);
        return NULL;
    }
    strncpy(temp, tp + 1, sizeof(temp) - 1);
    if (cidr_range != NULL) {
        *cidr_range = atoi(temp);
    }
    mask = mask >> atoi(temp);
    *ip = (*ip | mask);
    return ip;
}
