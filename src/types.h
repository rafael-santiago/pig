/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _PIG_TYPES_H
#define _PIG_TYPES_H 1

#include <stdlib.h>

typedef enum _pig_fields {
    kIpv4_version = 0, kIpv4_ihl, kIpv4_tos, kIpv4_tlen, kIpv4_id, kIpv4_flags,
    kIpv4_offset, kIpv4_ttl, kIpv4_protocol, kIpv4_checksum, kIpv4_src, kIpv4_dst,
    kTcp_src, kTcp_dst, kTcp_seq, kTcp_ackno, kTcp_size, kTcp_reserv, kTcp_urg, kTcp_ack,
    kTcp_psh, kTcp_rst, kTcp_syn, kTcp_fin, kTcp_wsize, kTcp_checksum, kTcp_urgp, kTcp_payload,
    kUdp_src, kUdp_dst, kUdp_size, kUdp_checksum, kUdp_payload, kRefresh, kRandom, kSignature, kUnk, kMaxPigFields
}pig_field_t;

typedef enum _pig_field_nature {
    kNatureSet = 0, kNatureRandom, kNatureRefresh, kMaxPigNature
}pig_field_nature_t;

typedef struct _pigsty_field {
    pig_field_t index;
    pig_field_nature_t nature;
    void *data;
    size_t dsize;
}pigsty_field_ctx;

typedef struct _pigsty_conf_set {
    pigsty_field_ctx field;
    struct _pigsty_conf_set *next;
}pigsty_conf_set_ctx;

typedef struct _pigsty_entry {
    pigsty_conf_set_ctx *conf;
    struct _pigsty_entry *next;
}pigsty_entry_ctx;

#endif
