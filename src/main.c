/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "types.h"
#include "pigsty.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>

static int should_exit = 0;

static int should_be_quiet = 0;

static char *get_option(const char *option, char *default_value, const int argc, char **argv);

static void sigint_watchdog(int signr);

static pigsty_entry_ctx *load_signatures(const char *signatures);

static void run_pig_run(const char *signatures, const char *timeout);

static char *get_option(const char *option, char *default_value, const int argc, char **argv) {
    static char retval[8192];
    int a;
    char temp[8192] = "";
    memset(temp, 0, sizeof(temp));
    temp[0] = '-';
    temp[1] = '-';
    strncpy(&temp[2], option, sizeof(temp) - 1);
    for (a = 0; a < argc; a++) {
        if (strcmp(argv[a], temp) == 0) {
            return "1";
        }
    }
    strcat(temp, "=");
    for (a = 0; a < argc; a++) {
        if (strstr(argv[a], temp) == argv[a]) {
            return argv[a] + strlen(temp);
        }
    }
    memset(retval, 0, sizeof(retval));
    if (default_value != NULL) {
        strncpy(retval, default_value, sizeof(retval) - 1);
    } else {
        return NULL;
    }
    return retval;
}

static void sigint_watchdog(int signr) {
    if (!should_be_quiet) {
        printf("\npig INFO: exiting... please wait...\n");
    }
    should_exit = 1;
}

static pigsty_entry_ctx *load_signatures(const char *signatures) {
    return NULL;
}

static void run_pig_run(const char *signatures, const char *timeout) {
    int timeo = 10;
    pigsty_entry_ctx *pigsty = NULL;
    if (timeout != NULL) {
        timeo = atoi(timeout);
    }
    if (!should_be_quiet) {
        printf("pig INFO: starting up pig engine...\n");
    }
    pigsty = load_signatures(signatures);
    if (pigsty == NULL) {
        printf("pig ERROR: aborted.\n");
        return;
    }
    if (!should_be_quiet) {
        printf("pig INFO: done.\n\n");
    }
    while (!should_exit) {
        if (!should_be_quiet) {
            printf("pig INFO: a packet based on signature was sent.\n");
        }
        sleep(timeo);
    }
}

int main(int argc, char **argv) {
    /*pigsty_entry_ctx *pigsty = NULL;
    if ((pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty")) == NULL) {
	printf("*** error! :S\n");
	return 1;
    }
    printf("*** success! ;)\n");
    del_pigsty_entry(pigsty);*/
    char *signatures = NULL;
    char *iface = NULL;
    char *timeout = NULL;
    char *tp = NULL;
    if (get_option("version", NULL, argc, argv) != NULL) {
        printf("pig v%s\n", PIG_VERSION);
        return 0;
    }
    if (argc > 2) {
        signatures = get_option("signatures", NULL, argc, argv);
        if (signatures == NULL) {
            printf("pig ERROR: --signatures option is missing.\n");
            return 1;
        }
        iface = get_option("iface", NULL, argc, argv);
        if (iface == NULL) {
            printf("pig ERROR: --iface option is missing.\n");
            return 1;
        }
        timeout = get_option("timeout", NULL, argc, argv);
        if (timeout != NULL) {
            for (tp = timeout; *tp != 0; tp++) {
                if (!isdigit(*tp)) {
                    printf("pig ERROR: an invalid timeout value was supplied.\n");
                    return 1;
                }
            }
        }
        should_be_quiet = (get_option("no-echo", NULL, argc, argv) != NULL);
        signal(SIGINT, sigint_watchdog);
        signal(SIGTERM, sigint_watchdog);
        run_pig_run(signatures, timeout);
    } else {
        printf("usage: %s --signatures=file.0,file.1,(...),file.n --iface=<nic> [--timeout=<in secs> --no-echo]\n", argv[0]);
    }
    return 0;
}
