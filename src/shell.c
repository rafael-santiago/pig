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
#include <unistd.h>
#include <termios.h>

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

static unsigned char getch(void);

static void add_char_to_cmdbuf(char cmdbuf[PIG_SHELL_CMDBUF_LEN], size_t *pos, const char c);

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

static unsigned char getch(void) {
    unsigned char c;
    struct termios attr, oldattr;
    tcgetattr(STDIN_FILENO,&attr);
    oldattr = attr;
    attr.c_lflag = ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &attr);
    read(STDIN_FILENO, &c, 1);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldattr);
    return c;
}

static void add_char_to_cmdbuf(char cmdbuf[PIG_SHELL_CMDBUF_LEN], size_t *pos, const char c) {
    size_t p, s;
    char temp[PIG_SHELL_CMDBUF_LEN];

    if (*pos >= PIG_SHELL_CMDBUF_LEN) {
        return;
    }

    if (c == 127) {
        if (*pos == 0) {
            return;
        }
        if (cmdbuf[*pos] == 0) {
            if (*pos > 0) {
                *pos -= 1;
            }
            cmdbuf[*pos] = 0;
        } else {
            for (p = *pos - 1; cmdbuf[p] != 0; p++) {
                cmdbuf[p] = cmdbuf[p + 1];
            }
            *pos -= 1;
        }
    } else if (c == 126) {
        if (cmdbuf[*pos] == 0) {
            return;
        }
        for (p = *pos; cmdbuf[p] != 0; p++) {
            cmdbuf[p] = cmdbuf[p + 1];
        }
    } else if (cmdbuf[*pos] == 0) {
        cmdbuf[*pos] = c;
    } else {
        // INFO(Rafael): We want to insert data into the buffer.
        memset(temp, 0, sizeof(temp));
        s = strlen(cmdbuf) - *pos;
        memcpy(temp, &cmdbuf[*pos], s);
        cmdbuf[*pos] = c;
        cmdbuf[*pos + 1] = 0;
        s = s % (PIG_SHELL_CMDBUF_LEN - strlen(cmdbuf));
        memcpy(&cmdbuf[*pos + 1], temp, s);
    }
}

static int shell_prompt(void) {
    char cmdbuf[PIG_SHELL_CMDBUF_LEN], lchar = '?', sk = '?';
    size_t c = 0, lc = 0, pc = 0;
    int exit_code = 0;
    int continue_line = 0;

    signal(SIGINT, shell_sigint_watchdog);
    signal(SIGTERM, shell_sigint_watchdog);

    memset(cmdbuf, 0, PIG_SHELL_CMDBUF_LEN);

    printf("%s", PIG_SHELL_PROMPT);
    fflush(stdout);

    while (!g_pig_shell_exit) {
        lchar = getch();

        if (lchar == 27) {
            getch();
            switch ((lchar=getch())) {
                case 'A': // INFO(Rafael): Up arrow.
                    // TODO(Rafael): History browse.
                    printf("(((( UP ))))\n");
                    break;

                case 'B': // INFO(Rafael): Down arrow.
                    // TODO(Rafael): History browse.
                    printf("(((( DOWN ))))\n");
                    break;

                case 'D': // INFO(Rafael): Left arrow.
                    if (lc > 0) {
                        lc--;
                        c--;
                        printf("\b");
                        fflush(stdout);
                    }
                    break;

                case 'C': // INFO(Rafael): Right arrow.
                    if (cmdbuf[lc] != 0 && lc < PIG_SHELL_CMDBUF_LEN) {
                        lc++;
                        c++;
                        printf("\033[1C");
                        fflush(stdout);
                    }
                    break;

                case 52:  // INFO(Rafael): End key.
                    sk = getch();
                    if (sk == 126) {
                        while (cmdbuf[c] != 0) {
                            lc++;
                            c++;
                            printf("\033[1C");
                            fflush(stdout);
                        }
                    } else {
                        printf("\b -- IGNORED key event, command buffer cleared. --\n", sk);
                        fflush(stdout);
                        goto shell_prompt_reset;
                    }
                    break;

                case 51: // INFO(Rafael): Delete key.
                    sk = getch();
                    if (sk == 126) {
                        add_char_to_cmdbuf(cmdbuf, &c, 126);
                        printf("\033[s\033[K");
                        printf("\r%s%s", (continue_line == 0) ? PIG_SHELL_PROMPT : PIG_SHELL_CONTINUE, &cmdbuf[pc]);
                        printf("\033[u");
                        fflush(stdout);
                    }
                    break;
            }
            continue;
        } else {
            if (lchar != '\r' && lchar != 127) {
                add_char_to_cmdbuf(cmdbuf, &c, lchar);
            }
            printf("\033[s");
            printf("\r%s%s", (continue_line == 0) ? PIG_SHELL_PROMPT : PIG_SHELL_CONTINUE, &cmdbuf[pc]);
            printf("\033[u");
            if (lchar != 126 && lchar != 127) {
                printf("\033[1C");
            }
            fflush(stdout);
        }

        if (g_pig_shell_exit) {
            printf("-- SIGNAL caught, bye! --\n");
            continue;
        }

        switch (lchar) {
            case 3:
                if (continue_line) {
                    printf("\n");
                    goto shell_prompt_reset;
                } else {
                    g_pig_shell_exit = 1;
                }
                break;

            case 127:
                if (lc > 0) {
                    add_char_to_cmdbuf(cmdbuf, &c, 127);
                    lc--;
                    printf("\b \033[s\033[K");
                    printf("\r%s%s", (continue_line == 0) ? PIG_SHELL_PROMPT : PIG_SHELL_CONTINUE, &cmdbuf[pc]);
                    printf("\033[u\033[1D");
                    fflush(stdout);
                }
                break;

            case '\r':
                printf("\n");
                fflush(stdout);
                if (c > 0 && cmdbuf[c - 1] == '\\') {
                    continue_line = 1;
                    printf("%s", PIG_SHELL_CONTINUE);
                    fflush(stdout);
                    lc = 0;
                    cmdbuf[c] = 0;
                    c--;
                    cmdbuf[c] = 0;
                    pc = c;
                } else {
                    while (cmdbuf[c] != 0) {
                        c++;
                    }
                    cmdbuf[c] = 0;
                    exit_code = shell_command_exec(cmdbuf);
shell_prompt_reset:
                    pc = 0;
                    continue_line = 0;
                    c = 0;
                    lc = 0;
                    memset(cmdbuf, 0, PIG_SHELL_CMDBUF_LEN);
                    printf("%s", PIG_SHELL_PROMPT);
                    fflush(stdout);
                }
                break;

            default:
                c = (c + 1) % PIG_SHELL_CMDBUF_LEN;
                lc++;
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
