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
                             (p)->next = NULL, (p)->conf = NULL )

#define new_pigsty_conf_set(c) ( (c) = (pigsty_conf_set_ctx *) pig_newseg(sizeof(pigsty_conf_set_ctx)),\
                                    (c)->next = NULL, (c)->field.data = NULL, (c)->field.dsize = 0, (c)->field.index = kUnk, (c)->field.nature = kNatureSet )


pigsty_conf_set_ctx *add_conf_to_pigsty_conf_set(pigsty_conf_set_ctx *conf,
                                                 const pig_field_t field_index,
                                                 const pig_field_t field_nature,
                                                 const void *data, size_t dsize);

void del_pigsty_entry(pigsty_entry_ctx *entries);

void del_pigsty_conf_set(pigsty_conf_set_ctx *confs);

#endif
