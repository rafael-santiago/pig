/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "pktslicer.h"
#include "endianess.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "arp.h"
#include <string.h>
#include <arpa/inet.h>

#define get_byte_from_u32(v, b) ( ( (v) >> ( 24 - ( (b) * 8 ) ) ) & 0xff )

typedef void *(*get_pkt_data_func)(const unsigned char *buf, const size_t buf_size, size_t *field_size);

struct pkt_field_boundaries {
    const char *name;
    size_t start_off, end_off;
    unsigned int mask;
    unsigned int rsh;
    int size;
    get_pkt_data_func get_data;
};

// INFO(Santiago): This states the slicer behavior for each relevant packet field.
//                 The basic "gear" for this kind of "machine" is: ( ( ( pkt + start_off ) & mask ) >> rsh )
//
//                               "Hocus pocus", "Língua de vaca", "Abracadabra", Ploc-tchum! :)
//
const struct pkt_field_boundaries g_pkt_fields[] = {
    { "eth.hwdst",      0,  5, 0xffffffff,  0,  6,                   NULL },
    { "eth.hwsrc",      6, 11, 0xffffffff,  0,  6,                   NULL },
    { "eth.type",      12, 13, 0xffffffff,  0,  2,                   NULL },
    { "ip.version",    14, 14, 0xf0000000, 28,  1,                   NULL },
    { "ip.ihl",        14, 14, 0x0f000000, 24,  1,                   NULL },
    { "ip.tos",        15, 15, 0xffffffff,  0,  1,                   NULL },
    { "ip.tlen",       16, 17, 0xffffffff,  0,  2,                   NULL },
    { "ip.id",         18, 19, 0xffffffff,  0,  2,                   NULL },
    { "ip.flags",      20, 20, 0xe0000000, 29,  1,                   NULL },
    { "ip.offset",     20, 21, 0x1fff0000, 16,  2,                   NULL },
    { "ip.ttl",        22, 22, 0xffffffff,  0,  1,                   NULL },
    { "ip.protocol",   23, 23, 0xffffffff,  0,  1,                   NULL },
    { "ip.checksum",   24, 25, 0xffffffff,  0,  2,                   NULL },
    { "ip.src",        26, 29, 0xffffffff,  0,  4,                   NULL },
    { "ip.dst",        30, 33, 0xffffffff,  0,  4,                   NULL },
    { "ip.payload",     0,  0,          0,  0, -1,        get_ip4_payload },
    { "tcp.src",       34, 35, 0xffffffff,  0,  2,                   NULL },
    { "tcp.dst",       36, 37, 0xffffffff,  0,  2,                   NULL },
    { "tcp.seqno",     38, 41, 0xffffffff,  0,  4,                   NULL },
    { "tcp.ackno",     42, 45, 0xffffffff,  0,  4,                   NULL },
    { "tcp.size",      46, 46, 0xf0000000, 28,  1,                   NULL },
    { "tcp.reserv",    46, 47, 0x0fc00000, 22,  1,                   NULL },
    { "tcp.flags",     46, 47, 0x003f0000, 16,  1,                   NULL },
    { "tcp.wsize",     48, 49, 0xffffffff,  0,  2,                   NULL },
    { "tcp.checksum",  50, 51, 0xffffffff,  0,  2,                   NULL },
    { "tcp.urgp",      52, 53, 0xffffffff,  0,  2,                   NULL },
    { "tcp.payload",    0,  0,          0,  0, -1,        get_tcp_payload },
    { "udp.src",       34, 35, 0xffffffff,  0,  2,                   NULL },
    { "udp.dst",       36, 37, 0xffffffff,  0,  2,                   NULL },
    { "udp.size",      38, 39, 0xffffffff,  0,  2,                   NULL },
    { "udp.checksum",  40, 41, 0xffffffff,  0,  2,                   NULL },
    { "udp.payload",    0,  0,          0,  0, -1,        get_udp_payload },
    { "icmp.type",     34, 34, 0xffffffff,  0,  1,                   NULL },
    { "icmp.code",     35, 35, 0xffffffff,  0,  1,                   NULL },
    { "icmp.checksum", 36, 37, 0xffffffff,  0,  2,                   NULL },
    { "icmp.payload",   0,  0,          0,  0, -1,       get_icmp_payload },
    { "arp.hwtype",    14,  15, 0xffffffff, 0,  2,                   NULL },
    { "arp.ptype",     16,  17, 0xffffffff, 0,  2,                   NULL },
    { "arp.hwlen",     18,  18, 0xffffffff, 0,  1,                   NULL },
    { "arp.plen",      19,  19, 0xffffffff, 0,  1,                   NULL },
    { "arp.opcode",    20,  21, 0xffffffff, 0,  2,                   NULL },
    { "arp.hwsrc",      0,  0,           0, 0, -1, get_arp_hw_src_payload },
    { "arp.psrc",       0,  0,           0, 0, -1, get_arp_pt_src_payload },
    { "arp.hwdst",      0,  0,           0, 0, -1, get_arp_hw_dst_payload },
    { "arp.pdst",       0,  0,           0, 0, -1, get_arp_pt_dst_payload }
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

void *get_pkt_field(const char *field, const unsigned char *buf, const size_t buf_size, size_t *field_size) {
    size_t p = 0;
    const unsigned char *mbuf_end = NULL;
    static unsigned int slice = 0;
    static unsigned char mbuf[0xffff] = "";
    static size_t mbuf_size = 0;
    get_pkt_data_func get_data = NULL;
    void *data = NULL;

    if (field == NULL || buf == NULL) {
        return NULL;
    }

    memcpy(mbuf, buf, buf_size);
    mbuf_size = buf_size;
    mbuf_end = mbuf + mbuf_size;
    for (p = 0; p < g_pkt_fields_size; p++) {
        if (strcmp(g_pkt_fields[p].name, field) == 0) {
            if (g_pkt_fields[p].size == -1) {
                if ((mbuf + 14) > mbuf_end || (get_data = g_pkt_fields[p].get_data) == NULL) {
                    return NULL;
                }
                data = get_data(buf + 14, buf_size - 14, field_size);
                if (data == NULL) {
                    return NULL;
                }
                memset(mbuf, 0, sizeof(mbuf));
                memcpy(mbuf, data, *field_size % sizeof(mbuf));
                free(data);
                return &mbuf[0];
            }
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
