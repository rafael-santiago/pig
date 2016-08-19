/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "types.h"
#include "options.h"
#include "run_pig_run.h"
#include "pktcraft.h"
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>

static void sigint_watchdog(int signr);

static void sigint_watchdog(int signr) {
    stop_pktcraft();
}

int main(int argc, char **argv) {
    int exit_code = 1;

    register_options(argc, argv);

    if (get_option("version", NULL) != NULL) {
        printf("pig v%s\n", PIG_VERSION);
        return 0;
    }

    if (argc > 1) {
        signal(SIGINT, sigint_watchdog);
        signal(SIGTERM, sigint_watchdog);
        exit_code = run_pig_run();
    } else {
        exit_code = pktcraft_help();
    }

    return exit_code;
}
