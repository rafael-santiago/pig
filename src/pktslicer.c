/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "pktslicer.h"
#include "endianess.h"
#include <string.h>
#include <arpa/inet.h>

#define get_byte_from_u32(v, b) ( ( (v) >> ( 24 - ( (b) * 8 ) ) ) & 0xff )

struct pkt_field_boundaries {
    const char *name;
    size_t start_off, end_off;
    unsigned int mask;
    unsigned int rsh;
    unsigned size;
};

// INFO(Santiago): This states the slicer behavior for each relevant packet field.
//                 The basic "gear" for this kind of "machine" is: ( ( ( pkt + start_off ) & mask ) >> rsh )
const struct pkt_field_boundaries g_pkt_fields[] = {
    { "eth.dst",     0,  5, 0xffffffff,  0, 6 },
    { "eth.src",     6, 11, 0xffffffff,  0, 6 },
    { "eth.type",   12, 13, 0xffffffff,  0, 2 },
    { "ip.version", 14, 14, 0xf0000000, 28, 1 },
    { "ip.ihl",     14, 14, 0x0f000000, 24, 1 },
    { "ip.tos",     15, 15, 0xffffffff,  0, 1 },
    { "ip.len",     16, 17, 0xffffffff,  0, 2 },
    { "ip.id",      18, 19, 0xffffffff,  0, 2 },
    { "ip.flags",   20, 20, 0xe0000000, 29, 1 },
    { "ip.fragoff", 20, 21, 0x1fff0000, 16, 2 },
    { "ip.ttl",     22, 22, 0xffffffff,  0, 1 },
    { "ip.proto",   23, 23, 0xffffffff,  0, 1 },
    { "ip.chsum",   24, 25, 0xffffffff,  0, 2 },
    { "ip.src",     26, 29, 0xffffffff,  0, 4 },
    { "ip.dst",     30, 33, 0xffffffff,  0, 4 },
    { "tcp.src",    34, 35, 0xffffffff,  0, 2 },
    { "tcp.dst",    36, 37, 0xffffffff,  0, 2 },
    { "tcp.seqno",  38, 41, 0xffffffff,  0, 4 },
    { "tcp.ackno",  42, 45, 0xffffffff,  0, 4 },
    { "tcp.len",    46, 46, 0xf0000000, 28, 1 },
    { "tcp.reserv", 46, 47, 0x0fc00000, 22, 1 },
    { "tcp.flags",  46, 47, 0x003f0000, 16, 1 },
    { "tcp.window", 48, 49, 0xffffffff,  0, 2 },
    { "tcp.chsum",  50, 51, 0xffffffff,  0, 2 },
    { "tcp.urgp",   52, 53, 0xffffffff,  0, 2 },
    { "udp.src",    34, 35, 0xffffffff,  0, 2 },
    { "udp.dst",    36, 37, 0xffffffff,  0, 2 },
    { "udp.len",    38, 39, 0xffffffff,  0, 2 },
    { "udp.chsum",  40, 41, 0xffffffff,  0, 2 }
};

const size_t g_pkt_fields_size = sizeof(g_pkt_fields) / sizeof(g_pkt_fields[0]);

/*
//  INFO(Santiago): By now this kind of feature is not relevant.
void set_pkt_field(const char *field, unsigned char *buf, size_t buf_size, const unsigned int value) {
    size_t p = 0;
    const unsigned char *buf_end = NULL;
    unsigned char *bp = NULL;
    unsigned int *slice = NULL;
    unsigned int temp_value = value;
    int b = 0, byte_nr = 0;
    if (field == NULL || buf == NULL) {
        return;
    }
    buf_end = buf + buf_size;
    for (p = 0; p < g_pkt_fields_size; p++) {
        if (strcmp(g_pkt_fields[p].name, field) == 0) {
            if (buf + g_pkt_fields[p].start_off + (g_pkt_fields[p].end_off - g_pkt_fields[p].start_off) > buf_end) {
                return;
            }
            bp = buf + g_pkt_fields[p].start_off;
            byte_nr = sizeof(value) - 1;
            for (b = 0; b < g_pkt_fields[p].size && bp != buf_end; b++, bp++, byte_nr--) {
                *bp = get_byte_from_u32(value, byte_nr);
            }
            return;
        }
    }
}
*/

void *get_pkt_field(const char *field, const unsigned char *buf, size_t buf_size, size_t *field_size) {
    size_t p = 0;
    const unsigned char *mbuf_end = NULL;
    static unsigned int slice = 0;
    static unsigned char mbuf[0xffff] = "";
    static size_t mbuf_size = 0;
    if (field == NULL || buf == NULL) {
        return NULL;
    }
    memcpy(mbuf, buf, buf_size);
    mbuf_size = buf_size;
    mbuf_end = mbuf + mbuf_size;
    for (p = 0; p < g_pkt_fields_size; p++) {
        if (strcmp(g_pkt_fields[p].name, field) == 0) {
            if (mbuf + g_pkt_fields[p].start_off + (g_pkt_fields[p].end_off - g_pkt_fields[p].start_off) > mbuf_end) {
                return NULL;
            }
            if (field_size != NULL) {
                *field_size = g_pkt_fields[p].size;
            }
            if (g_pkt_fields[p].mask != 0xffffffff) {
                slice = *((unsigned int *)(mbuf + g_pkt_fields[p].start_off));
                if (little_endian()) {
                    slice = htonl(slice);
                }
                slice = (slice & g_pkt_fields[p].mask) >> g_pkt_fields[p].rsh;
                return &slice;
            }
            return (mbuf + g_pkt_fields[p].start_off);
        }
    }
    return NULL;
}
