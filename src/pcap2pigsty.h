/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_PCAP2PIGSTY_H
#define PIG_PCAP2PIGSTY_H 1

int pcap2pigsty(const char *pigsty_filepath, const char *pcap_filepath, const char *signature_fmt, const int incl_ethframe);

#endif
