/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "shell.h"
#include "options.h"
#include "watchdogs.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

#define PIG_SHELL_CMDBUF_LEN 0xffff

#define PIG_SHELL_PROMPT "~ "

#define PIG_SHELL_CONTINUE "... "

typedef int (*pigshell_cmdtrap)(const char *cmd);

struct compound_cmd_traps_ctx {
    const char *cmd;
    pigshell_cmdtrap trap;
};

static int shell_help(void);

static int shell_prompt(void);

static int g_pig_shell_exit = 0;

static int shell_command_exec(const char *cmd);

static int exec_compound_cmd(const char *cmd);

static struct compound_cmd_traps_ctx g_pigshell_traps[] = {
    { "[",      NULL },
    { "flood ",  NULL },
    { "oink ",   NULL },
    { "pigsty ", NULL },
    { "set ",    NULL },
    { "unset ",  NULL }
};

static size_t g_pigshell_traps_nr = sizeof(g_pigshell_traps) / sizeof(g_pigshell_traps[0]);

static struct compound_cmd_traps_ctx g_pigshell_pigsty_traps[] = {
    { "ld ", NULL },
    { "ls ", NULL },
    { "rm ", NULL }
};

static size_t g_pigshell_pigsty_traps_nr = sizeof(g_pigshell_pigsty_traps) / sizeof(g_pigshell_pigsty_traps[0]);

int shell(void) {
    if (get_option("help", NULL) != NULL) {
        return shell_help();
    }
    return shell_prompt();
}

static int shell_help(void) {
    printf("usage: pig --sub-task=shell [general pig options]\n");
    return 0;
}

int quit_shell(void) {
    g_pig_shell_exit = 1;
}

static int shell_prompt(void) {
    char cmdbuf[PIG_SHELL_CMDBUF_LEN], lchar = '?';
    size_t c = 0;
    int exit_code = 0;

    signal(SIGINT, shell_sigint_watchdog);
    signal(SIGTERM, shell_sigint_watchdog);

    memset(cmdbuf, 0, PIG_SHELL_CMDBUF_LEN);

    printf("%s", PIG_SHELL_PROMPT);

    while (!g_pig_shell_exit) {
        lchar = cmdbuf[c] = fgetc(stdin);

        if (g_pig_shell_exit) {
            printf("-- SIGNAL caught, bye! --\n");
            continue;
        }

        switch (lchar) {
            case '\n':
                if (c > 0 && cmdbuf[c - 1] == '\\') {
                    printf("%s", PIG_SHELL_CONTINUE);
                    c--;
                } else {
                    cmdbuf[c] = 0;
                    exit_code = shell_command_exec(cmdbuf);
                    c = 0;
                    memset(cmdbuf, 0, PIG_SHELL_CMDBUF_LEN);
                    printf("%s", PIG_SHELL_PROMPT);
                }
                break;

            default:
                c = (c + 1) % PIG_SHELL_CMDBUF_LEN;
                break;
        }
    }
    printf("\n");
    return 0;
}

static int shell_command_exec(const char *cmd) {
    const char *cp = cmd;
    int exit_code = 0;

    if (cp == NULL) {
        return 1;
    }

    if (*cmd == 0) {
        return 0;
    }

    while (*cp == ' ' && *cp != 0 && !g_pig_shell_exit) {
        cp++;
    }

    switch (*cp) {
        case '!': // INFO(Rafael): "Outsider" command mark...
            return system(cp+1);
            break;

        default:
            if (strcmp(cp, "exit") == 0 || strcmp(cp, "quit") == 0) {
                quit_shell();
                return 0;
            }

            if ((exit_code = exec_compound_cmd(cp)) == -1) {
                printf("Unknown command: '%s'.\n", cmd);
                exit_code = 1;
            }
            break;
    }

    return exit_code;
}

static int exec_compound_cmd(const char *cmd) {
    size_t t = 0;

    while (t < g_pigshell_traps_nr) {
        if (g_pigshell_traps[t].trap != NULL &&
            strstr(cmd, g_pigshell_traps[t].cmd) == cmd) {
            return g_pigshell_traps[t].trap(cmd + strlen(g_pigshell_traps[t].cmd) + 1);
        }
        t++;
    }

    return -1;
}
