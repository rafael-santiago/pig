/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "watchdogs.h"
#include "pktcraft.h"
#include "shell.h"

void pktcrafter_sigint_watchdog(int signr) {
    stop_pktcraft();
}

void shell_sigint_watchdog(int signr) {
    quit_shell();
}
