/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef _PIG_LISTS_H
#define _PIG_LISTS_H 1

#include "types.h"

#define new_pigsty_entry(p) ( (p) = (pigsty_entry_ctx *) pig_newseg(sizeof(pigsty_entry_ctx)),\
                             (p)->next = NULL, (p)->conf = NULL, (p)->signature_name = NULL )

#define new_pigsty_conf_set(c) ( (c) = (pigsty_conf_set_ctx *) pig_newseg(sizeof(pigsty_conf_set_ctx)),\
                                    (c)->next = NULL, (c)->field = (pigsty_field_ctx *) pig_newseg(sizeof(pigsty_field_ctx)), (c)->field->data = NULL, (c)->field->index = kUnk )


pigsty_conf_set_ctx *add_conf_to_pigsty_conf_set(pigsty_conf_set_ctx *conf,
                                                 const pig_field_t field_index,
                                                 const void *data, size_t dsize);

pigsty_entry_ctx *add_signature_to_pigsty_entry(pigsty_entry_ctx *entries, const char *signature);

pigsty_entry_ctx *get_pigsty_entry_signature_name(const char *signature_name, pigsty_entry_ctx *entries);

pigsty_entry_ctx *get_pigsty_entry_tail(pigsty_entry_ctx *entries);

pigsty_field_ctx *get_pigsty_conf_set_field(const int index, pigsty_conf_set_ctx *conf);

void del_pigsty_entry(pigsty_entry_ctx *entries);

void del_pigsty_conf_set(pigsty_conf_set_ctx *confs);

#endif
