/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "lists.h"
#include "memory.h"
#include "netmask.h"
#include "to_ipv4.h"
#include "mkrnd.h"
#include "strglob.h"
#include <string.h>

static pigsty_conf_set_ctx *get_pigsty_conf_set_tail(pigsty_conf_set_ctx *conf);

pigsty_conf_set_ctx *add_conf_to_pigsty_conf_set(pigsty_conf_set_ctx *conf,
                                                 const pig_field_t field_index,
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
    p->field->index = field_index;
    p->field->data = pig_newseg(dsize + 1);
    memset(p->field->data, 0, dsize + 1);
    memcpy(p->field->data, data, dsize);
    p->field->dsize = dsize;
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
        if (p->field->data != NULL) {
            free(p->field->data);
        }
        free(p->field);
    }
}

pigsty_entry_ctx *add_signature_to_pigsty_entry(pigsty_entry_ctx *entries, const char *signature) {
    pigsty_entry_ctx *head = entries, *p;
    if (head == NULL) {
        new_pigsty_entry(head);
        p = head;
    } else {
        p = get_pigsty_entry_tail(entries);
        new_pigsty_entry(p->next);
        p = p->next;
    }
    p->signature_name = (char *) pig_newseg(strlen(signature) + 1);
    memset(p->signature_name, 0, strlen(signature) + 1);
    strncpy(p->signature_name, signature, strlen(signature));
    return head;
}

pigsty_entry_ctx *get_pigsty_entry_tail(pigsty_entry_ctx *entries) {
    pigsty_entry_ctx *p;
    for (p = entries; p->next; p = p->next);
    return p;
}

pigsty_entry_ctx *get_pigsty_entry_signature_name(const char *signature_name, pigsty_entry_ctx *entries) {
    pigsty_entry_ctx *ep;
    for (ep = entries; ep != NULL; ep = ep->next) {
        if (strcmp(ep->signature_name, signature_name) == 0) {
            return ep;
        }
    }
    return NULL;
}

pigsty_field_ctx *get_pigsty_conf_set_field(const int index, pigsty_conf_set_ctx *conf) {
    pigsty_conf_set_ctx *cp;
    for (cp = conf; cp != NULL; cp = cp->next) {
	if (cp->field->index == index) {
	    return cp->field;
	}
    }
    return NULL;
}

pigsty_conf_set_ctx *get_pigsty_conf_set_by_index(const size_t index, pigsty_conf_set_ctx *conf) {
    size_t i = 0;
    pigsty_conf_set_ctx *cp = NULL;
    for (cp = conf; cp != NULL; cp = cp->next, i++) {
        if (i == index) {
            return cp;
        }
    }
    return NULL;
}

size_t get_pigsty_conf_set_count(pigsty_conf_set_ctx *conf) {
    pigsty_conf_set_ctx *cp = NULL;
    size_t count = 0;
    for (cp = conf; cp != NULL; cp = cp->next) {
        count++;
    }
    return count;
}

size_t get_pigsty_entry_count(const pigsty_entry_ctx *entries) {
    size_t count = 0;
    const pigsty_entry_ctx *ep = NULL;
    for (ep = entries; ep != NULL; ep = ep->next) {
        count++;
    }
    return count;
}

const pigsty_entry_ctx *get_pigsty_entry_by_index(const size_t index, const pigsty_entry_ctx *entries) {
    const pigsty_entry_ctx *ep = NULL;
    size_t count = 0;
    for (ep = entries; ep != NULL; ep = ep->next) {
        if (count == index) {
            return ep;
        }
        count++;
    }
    return NULL;
}

void del_pig_target_addr(pig_target_addr_ctx *addrs) {
    pig_target_addr_ctx *t, *p;
    for (t = p = addrs; t; p = t) {
        t = p->next;
        if (p->addr != NULL) {
            free(p->addr);
        }
    }
}

static pig_target_addr_ctx *get_pig_target_addr_tail(pig_target_addr_ctx *addrs) {
    pig_target_addr_ctx *a = NULL;
    for (a = addrs; a->next != NULL; a = a->next);
    return a;
}

pig_target_addr_ctx *add_target_addr_to_pig_target_addr(pig_target_addr_ctx *addrs, const char *range) {
    pig_target_addr_ctx *head = addrs, *p = NULL;
    if (head == NULL) {
        new_pig_target_addr(head);
        p = head;
    } else {
        p = get_pig_target_addr_tail(head);
        new_pig_target_addr(p->next);
        p = p->next;
    }
    p->type = get_range_type(range);
    switch (p->type) {

        case kAddr:
            p->addr = to_ipv4(range);
            break;

        case kWild:
            p->addr = to_ipv4_mask(range);
            break;

        case kCidr:
            p->addr = to_ipv4_cidr(range, &p->cidr_range);
            break;

        default:
            break;

    }
    p->v = 4;
    p->asize = sizeof(int);
    return head;
}

size_t get_pig_target_addr_count(pig_target_addr_ctx *addrs) {
    size_t c = 0;
    pig_target_addr_ctx * a = NULL;
    for (a = addrs; a != NULL; a = a->next) {
        c++;
    }
    return c;
}

unsigned int get_ipv4_pig_target_by_index(const size_t index, pig_target_addr_ctx *addrs) {
    size_t i = 0;
    pig_target_addr_ctx *ap = NULL;
    unsigned int ipv4_addr = 0;
    for (ap = addrs; ap != NULL; ap = ap->next) {
        if (i == index) {
            break;
        }
        i++;
    }
    if (ap != NULL) {
        ipv4_addr = mk_rnd_ipv4_by_mask(ap);
    }
    return ipv4_addr;
}

pig_hwaddr_ctx *add_hwaddr_to_pig_hwaddr(pig_hwaddr_ctx *hwaddr, const unsigned char ph_addr[6], const unsigned int nt_addr[4], const int version) {
    pig_hwaddr_ctx *head = hwaddr, *p = NULL;
    if (head != NULL) {
        p = get_pig_hwaddr_tail(hwaddr);
        new_pig_hwaddr(p->next);
        p = p->next;
    } else {
        new_pig_hwaddr(head);
        p = head;
    }
    p->ip_v = version;

    p->ph_addr[0] = ph_addr[0];
    p->ph_addr[1] = ph_addr[1];
    p->ph_addr[2] = ph_addr[2];
    p->ph_addr[3] = ph_addr[3];
    p->ph_addr[4] = ph_addr[4];
    p->ph_addr[5] = ph_addr[5];

    p->nt_addr[0] = nt_addr[0];
    if (p->ip_v == 6) {
        p->nt_addr[1] = nt_addr[1];
        p->nt_addr[2] = nt_addr[2];
        p->nt_addr[3] = nt_addr[3];
    }
    return head;
}

void del_pig_hwaddr(pig_hwaddr_ctx *hwaddr) {
    pig_hwaddr_ctx *t = NULL, *p = NULL;
    for (t = p = hwaddr; t; p = t) {
        t = p->next;
        free(p);
    }
}

unsigned char *get_ph_addr_from_pig_hwaddr(const unsigned int nt_addr[4], const pig_hwaddr_ctx *hwaddr) {
    unsigned char *retval = NULL;
    const pig_hwaddr_ctx *p = NULL;
    for (p = hwaddr; p != NULL && retval == NULL; p = p->next) {
        if (memcmp(p->nt_addr, nt_addr, sizeof(p->nt_addr)) == 0) {
            retval = (unsigned char *)&p->ph_addr[0];
        }
    }
    return retval;
}

pig_hwaddr_ctx *get_pig_hwaddr_tail(pig_hwaddr_ctx *hwaddr) {
    pig_hwaddr_ctx *p = NULL;
    if (hwaddr == NULL) {
        return NULL;
    }
    for (p = hwaddr; p->next != NULL; p = p->next);
    return p;
}

int rm_pigsty_entry(pigsty_entry_ctx **entries, const char *signature_name) {
    pigsty_entry_ctx *ep = NULL, *lp = NULL, *np = NULL;
    int rt = 0;

    if (entries == NULL || signature_name == NULL) {
        return 0;
    }

    ep = *entries;

    while (ep != NULL) {
        if (strglob(ep->signature_name, signature_name)) {
            np = ep->next;

            if (lp == NULL) {
                *entries = ep->next;
                ep->next = NULL;
            } else {
                lp->next = ep->next;
                ep->next = NULL;
            }

            del_pigsty_entry(ep);
            rt++;

            ep = np;
        } else {
            lp = ep;
            ep = ep->next;
        }
    }

    return rt;
}
