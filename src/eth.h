/*
 *                        Copyright (C) 2014, 2015 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_ETH_H
#define PIG_ETH_H 1

#include <stdlib.h>

#define ETHER_TYPE_ARP      0x0806
#define ETHER_TYPE_IP       0x0800

struct ethernet_frame {
    unsigned char dest_hw_addr[6];
    unsigned char src_hw_addr[6];
    unsigned short ether_type;
    unsigned char *payload;
    size_t payload_size;
};

struct ethernet_frame *parse_ethernet_frame(const unsigned char *buf, const size_t bsize);

unsigned char *mk_ethernet_frame(size_t *bsize, struct ethernet_frame eth);

#endif
