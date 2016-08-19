/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_LISTS_H
#define PIG_LISTS_H 1

#include "types.h"

#define new_pigsty_entry(p) ( (p) = (pigsty_entry_ctx *) pig_newseg(sizeof(pigsty_entry_ctx)),\
                             (p)->next = NULL, (p)->conf = NULL, (p)->signature_name = NULL )

#define new_pigsty_conf_set(c) ( (c) = (pigsty_conf_set_ctx *) pig_newseg(sizeof(pigsty_conf_set_ctx)),\
                                    (c)->next = NULL, (c)->field = (pigsty_field_ctx *) pig_newseg(sizeof(pigsty_field_ctx)), (c)->field->data = NULL, (c)->field->index = kUnk )

#define new_pig_target_addr(t) ( (t) = (pig_target_addr_ctx *) pig_newseg(sizeof(pig_target_addr_ctx)),\
                                 (t)->next = NULL, (t)->asize = 0, (t)->addr = NULL, (t)->type = kNone, (t)->v = 0, (t)->cidr_range = 0 )

#define new_pig_hwaddr(h) ( (h) = (pig_hwaddr_ctx *) pig_newseg(sizeof(pig_hwaddr_ctx)),\
                            (h)->next = NULL, memset(&(h)->nt_addr[0], 0, sizeof((h)->nt_addr)), memset(&(h)->ph_addr[0], 0, sizeof((h)->ph_addr)), (h)->ip_v = 0 )

pigsty_conf_set_ctx *add_conf_to_pigsty_conf_set(pigsty_conf_set_ctx *conf,
                                                 const pig_field_t field_index,
                                                 const void *data, size_t dsize);

pigsty_entry_ctx *add_signature_to_pigsty_entry(pigsty_entry_ctx *entries, const char *signature);

pigsty_entry_ctx *get_pigsty_entry_signature_name(const char *signature_name, pigsty_entry_ctx *entries);

pigsty_entry_ctx *get_pigsty_entry_tail(pigsty_entry_ctx *entries);

pigsty_field_ctx *get_pigsty_conf_set_field(const int index, pigsty_conf_set_ctx *conf);

void del_pigsty_entry(pigsty_entry_ctx *entries);

void del_pigsty_conf_set(pigsty_conf_set_ctx *confs);

pigsty_conf_set_ctx *get_pigsty_conf_set_by_index(const size_t index, pigsty_conf_set_ctx *conf);

size_t get_pigsty_conf_set_count(pigsty_conf_set_ctx *conf);

size_t get_pigsty_entry_count(const pigsty_entry_ctx *entries);

const pigsty_entry_ctx *get_pigsty_entry_by_index(const size_t index, const pigsty_entry_ctx *entries);

void del_pig_target_addr(pig_target_addr_ctx *addrs);

pig_target_addr_ctx *add_target_addr_to_pig_target_addr(pig_target_addr_ctx *addrs, const char *range);

size_t get_pig_target_addr_count(pig_target_addr_ctx *addrs);

//pig_target_addr_ctx *get_pig_target_addr_by_index(const size_t index, pig_target_addr_ctx *addrs);

unsigned int get_ipv4_pig_target_by_index(const size_t index, pig_target_addr_ctx *addrs);

pig_hwaddr_ctx *add_hwaddr_to_pig_hwaddr(pig_hwaddr_ctx *hwaddr, const unsigned char ph_addr[6], const unsigned int nt_addr[4], const int version);

void del_pig_hwaddr(pig_hwaddr_ctx *hwaddr);

unsigned char *get_ph_addr_from_pig_hwaddr(const unsigned int nt_addr[4], const pig_hwaddr_ctx *hwaddr);

pig_hwaddr_ctx *get_pig_hwaddr_tail(pig_hwaddr_ctx *hwaddr);

#endif
