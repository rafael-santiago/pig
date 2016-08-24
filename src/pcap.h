/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_PCAP_H
#define PIG_PCAP_H 1

#include "types.h"

pcap_file_ctx *ld_pcap_file(const char *filepath);

void close_pcap_file(pcap_file_ctx *file);

int save_pcap_file(const pcap_file_ctx *file);

#endif
