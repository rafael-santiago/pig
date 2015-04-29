/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "lists.h"
#include "memory.h"
#include <string.h>

static pigsty_conf_set_ctx *get_pigsty_conf_set_tail(pigsty_conf_set_ctx *conf);

pigsty_conf_set_ctx *add_conf_to_pigsty_conf_set(pigsty_conf_set_ctx *conf,
                                                 const pig_field_t field_index,
                                                 const pig_field_t field_nature,
                                                 const void *data, size_t dsize) {
    pigsty_conf_set_ctx *head = conf, *p;
    if (head == NULL) {
        new_pigsty_conf_set(head);
        p = head;
    } else {
        p = get_pigsty_conf_set_tail(conf);
        new_pigsty_conf_set(p->next);
        p = p->next;
    }
    p->field.nature = field_nature;
    if (field_nature == kNatureSet) {
        p->field.data = pig_newseg(dsize);
        memcpy(p->field.data, data, dsize);
        p->field.dsize = dsize;
    }
    return head;
}

static pigsty_conf_set_ctx *get_pigsty_conf_set_tail(pigsty_conf_set_ctx *conf) {
    pigsty_conf_set_ctx *p;
    for (p = conf; p->next != NULL; p = p->next);
    return p;
}

void del_pigsty_entry(pigsty_entry_ctx *entries) {
    pigsty_entry_ctx *t, *p;
    for (t = p = entries; t; p = t) {
        t = p->next;
        del_pigsty_conf_set(p->conf);
        free(p);
    }
}

void del_pigsty_conf_set(pigsty_conf_set_ctx *confs) {
    pigsty_conf_set_ctx *t, *p;
    for (t = p = confs; t; p = t) {
        t = p->next;
        if (p->field.data != NULL) {
            free(p->field.data);
        }
    }
}
