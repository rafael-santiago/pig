/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#ifndef PIG_WATCHDOGS_H
#define PIG_WATCHDOGS_H 1

void pktcrafter_sigint_watchdog(int signr);

void shell_sigint_watchdog(int signr);

#endif
