/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "options.h"
#include <string.h>
#include <stdio.h>

static char **g_argv = NULL;

static int g_argc = 0;

void register_options(const int argc, char **argv) {
    g_argc = argc;
    g_argv = argv;
}

char *get_option(const char *option, char *default_value) {
    static char retval[8192];
    int a;
    char temp[8192] = "";

    if (g_argc <= 0 || g_argv == NULL) {
        if (default_value == NULL) {
            return NULL;
        }

        sprintf(retval, "%s", default_value);
        goto get_option_epilogue;
    }

    memset(temp, 0, sizeof(temp));
    temp[0] = '-';
    temp[1] = '-';

    strncpy(&temp[2], option, sizeof(temp) - 1);
    for (a = 0; a < g_argc; a++) {
        if (strcmp(g_argv[a], temp) == 0) {
            sprintf(retval, "1");
            goto get_option_epilogue;
        }
    }

    strncat(temp, "=", sizeof(temp) - 1);

    for (a = 0; a < g_argc; a++) {
        if (strstr(g_argv[a], temp) == g_argv[a]) {
            sprintf(retval, "%s", g_argv[a] + strlen(temp));
            goto get_option_epilogue;
        }
    }

    memset(retval, 0, sizeof(retval));

    if (default_value != NULL) {
        strncpy(retval, default_value, sizeof(retval) - 1);
    } else {
        return NULL;
    }

get_option_epilogue:

    return &retval[0];
}

char **get_argv(void) {
    return g_argv;
}

int get_argc(void) {
    return g_argc;
}
