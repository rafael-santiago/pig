/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_TYPES_H
#define PIG_TYPES_H 1

#include <stdlib.h>

#define PIG_VERSION "0.0.2"

typedef enum _pig_fields {
    kIpv4_version = 0, kIpv4_ihl, kIpv4_tos, kIpv4_tlen, kIpv4_id, kIpv4_flags,
    kIpv4_offset, kIpv4_ttl, kIpv4_protocol, kIpv4_checksum, kIpv4_src, kIpv4_dst, kIpv4_payload,
    kTcp_src, kTcp_dst, kTcp_seq, kTcp_ackno, kTcp_size, kTcp_reserv, kTcp_urg, kTcp_ack,
    kTcp_psh, kTcp_rst, kTcp_syn, kTcp_fin, kTcp_wsize, kTcp_checksum, kTcp_urgp, kTcp_payload,
    kUdp_src, kUdp_dst, kUdp_size, kUdp_checksum, kUdp_payload, kIcmp_type, kIcmp_code, kIcmp_checksum,
    kIcmp_payload, kArp_hwtype, kArp_ptype, kArp_hwlen, kArp_plen, kArp_opcode, kArp_hwsrc, kArp_psrc,
    kArp_hwdst, kArp_pdst, kSignature, kRefresh, kRandom, kUnk, kMaxPigFields
}pig_field_t;

typedef struct _pigsty_field {
    pig_field_t index;
    void *data;
    size_t dsize;
}pigsty_field_ctx;

typedef struct _pigsty_conf_set {
    pigsty_field_ctx *field;
    struct _pigsty_conf_set *next;
}pigsty_conf_set_ctx;

typedef struct _pigsty_entry {
    char *signature_name;
    pigsty_conf_set_ctx *conf;
    struct _pigsty_entry *next;
}pigsty_entry_ctx;

typedef enum _pig_addr_range_type {
    kNone,
    kWild,
    kCidr,
    kAddr
}pig_addr_range_type_t;

typedef struct _pig_target_addr {
    pig_addr_range_type_t type;
    unsigned char v;
    void *addr;
    size_t asize;
    unsigned int cidr_range;
    struct _pig_target_addr *next;
}pig_target_addr_ctx;

typedef struct _pig_hwaddr {
    int ip_v;
    unsigned char ph_addr[6];
    unsigned int nt_addr[4];
    struct _pig_hwaddr *next;
}pig_hwaddr_ctx;

#endif
