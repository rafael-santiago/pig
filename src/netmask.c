/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "netmask.h"
#include "pigsty.h"
#include <ctype.h>
#include <string.h>

pig_addr_range_type_t get_range_type(const char *range) {
    const char *rp = NULL;
    char temp[0xff];
    int is = 0;
    size_t t = 0;
    size_t oc = 0;
    if (verify_ipv4_addr(range) && strcmp(range, "north-american-ip") != 0 &&
                                   strcmp(range, "south-american-ip") != 0 &&
                                   strcmp(range, "european-ip")       != 0 &&
                                   strcmp(range, "asian-ip")          != 0) {
        return kAddr;
    }
    //  WARN(Santiago): is a masked addr?
    is = 1;
    if (strcmp(range, "*") != 0) {
        memset(temp, 0, sizeof(temp));
        for (rp = range; *rp != 0 && is; rp++) {
            if (*rp == '.' || *(rp + 1) == 0) {
                oc++;
                if (*(rp+1) == 0) {
                    temp[t] = *(rp + 1);
                }
                is = (strcmp(temp, "*") == 0 || (atoi(temp) >= 0 && atoi(temp) <= 255));
                memset(temp, 0, sizeof(temp));
                t = 0;
            } else {
                temp[t] = *rp;
                t = (t + 1) % sizeof(temp);
                is = isdigit(*rp);
            }
        }
    } else {
        return kWild;
    }

    if (is && oc == 3 && *rp == 0) {
        return kWild;
    }

    //  WARN(Santiago): is a cidr?
    is = 1;
    oc = 0;
    memset(temp, 0, sizeof(temp));
    for (rp = range; *rp != 0 && is && *rp != '/'; rp++) {
        if (*rp == '.' || *(rp + 1) == '/') {
            if (*rp == '.') {
                oc++;
            }
            if (*(rp+1) == '/') {
                temp[t] = *rp;
            }
            is = (atoi(temp) >= 0 && atoi(temp) <= 255);
            memset(temp, 0, sizeof(temp));
            t = 0;
        } else {
            temp[t] = *rp;
            t = (t + 1) % sizeof(temp);
            is = isdigit(*rp);
        }
    }

    if (is && *rp == '/' && oc == 3) {
        is = (atoi(rp+1) > 0 && atoi(rp+1) < 32);
        if (is) {
            rp++;
            while (*rp != 0) {
                if (!isdigit(*rp)) {
                    return kNone;
                }
                rp++;
            }
            return kCidr;
        }
    }

    return kNone;
}
