/*
 *                        Copyright (C) 2014, 2015 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_ARP_H
#define PIG_ARP_H 1

#include "types.h"
#include <stdlib.h>

#define ARP_HW_TYPE_ETHERNET    1
#define ARP_HW_TYPE_IEEE802     6
#define ARP_HW_TYPE_ARCNET      7
#define ARP_HW_TYPE_FRELAY      15
#define ARP_HW_TYPE_ATM         16
#define ARP_HW_TYPE_HDLC        17
#define ARP_HW_TYPE_FCHANNEL    18
#define ARP_HW_TYPE_ATM_        19
#define ARP_HW_TYPE_SLINE       20

#define ARP_OPCODE_REQUEST      1
#define ARP_OPCODE_REPLY        2
#define ARP_OPCODE_RREQUEST     3
#define ARP_OPCODE_RREPLY       4
#define ARP_OPCODE_DREQUEST     5
#define ARP_OPCODE_DREPLY       6
#define ARP_OPCODE_DRERROR      7
#define ARP_OPCODE_INREQUEST    8
#define ARP_OPCODE_INREPLY      9

#define ARP_PROTO_TYPE_IP       0x0800

#define arp_header_free(a) {\
    if ((a)->src_hw_addr != NULL) free((a)->src_hw_addr);\
    if ((a)->src_pt_addr != NULL) free((a)->src_pt_addr);\
    if ((a)->src_hw_addr != NULL) free((a)->dest_hw_addr);\
    if ((a)->src_pt_addr != NULL) free((a)->dest_pt_addr);\
}

struct arp {
    unsigned short hwtype;
    unsigned short ptype;
    unsigned char hw_addr_len;
    unsigned char pt_addr_len;
    unsigned short opcode;
    unsigned char *src_hw_addr;
    unsigned char *src_pt_addr;
    unsigned char *dest_hw_addr;
    unsigned char *dest_pt_addr;
};

struct arp *parse_arp_dgram(const unsigned char *buf, const size_t bsize);

unsigned char *mk_arp_dgram(size_t *bsize, const struct arp arph);

unsigned char *mac2byte(const char *mac, size_t len);

#include "linux/native_arp.h"

#endif
