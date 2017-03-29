/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_PKTCRAFT_H
#define PIG_PKTCRAFT_H 1

#include "types.h"

struct pktcraft_options_ctx {
    char *signatures;
    char *targets;
    char *gw_addr;
    char *loiface;
    char *nt_mask;
    char *single_test;
    char *no_gateway;
    int should_be_quiet;
    int timeo;
    pigsty_entry_ctx *pigsty;
};

void stop_pktcraft();

int pktcraft();

int pktcraft_help();

int parse_pktcraft_options(struct pktcraft_options_ctx *options);

int exec_pktcraft(const struct pktcraft_options_ctx user_options);

#endif
