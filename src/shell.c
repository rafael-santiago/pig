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
#include "types.h"
#include "pigsty.h"
#include "lists.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <termios.h>

#define PIG_SHELL_CMDBUF_LEN 0xffff

#define PIG_SHELL_PROMPT "~ "

#define PIG_SHELL_CONTINUE "... "

#define PIG_MAX_HISTORY_NR 100

#define PIG_SHELL_ESCAPE_KEY            0x1b
#define PIG_SHELL_UP_KEY                0x41
#define PIG_SHELL_DOWN_KEY              0x42
#define PIG_SHELL_LEFT_KEY              0x44
#define PIG_SHELL_RIGHT_KEY             0x43
#define PIG_SHELL_END_KEY               0x34
#define PIG_SHELL_DELETE_KEY            0x33
#define PIG_SHELL_CTRL_C                0x03
#define PIG_SHELL_BACKSPACE_KEY         0x7f

typedef int (*pigshell_cmdtrap)(const char *cmd);

struct compound_cmd_traps_ctx {
    const char *cmd;
    pigshell_cmdtrap trap;
};

static int shell_help(void);

static int shell_prompt(void);

static int g_pig_shell_exit = 0;

static pigsty_entry_ctx *g_pigsty_head = NULL, *g_pigsty_tail = NULL;

static int shell_command_exec(const char *cmd);

static int exec_compound_cmd(const char *cmd);

static unsigned char getch(void);

static void add_char_to_cmdbuf(char cmdbuf[PIG_SHELL_CMDBUF_LEN], size_t *pos, const char c);

static int append_pigsty_data(pigsty_entry_ctx *data);

static int add_pigsty_cmdtrap(const char *cmd);

static int pigsty_ld_cmdtrap(const char *cmd);

static int pigsty_ls_cmdtrap(const char *cmd);

static int pigsty_rm_cmdtrap(const char *cmd);

static int pigsty_clear_cmdtrap(const char *cmd);

static int pigsty_cmdtrap(const char *cmd);

static struct compound_cmd_traps_ctx g_pigshell_traps[] = {
    { "[",       add_pigsty_cmdtrap },
    { "flood ",  NULL               },
    { "oink ",   NULL               },
    { "pigsty ", pigsty_cmdtrap     },
    { "set ",    NULL               },
    { "unset ",  NULL               }
};

static size_t g_pigshell_traps_nr = sizeof(g_pigshell_traps) / sizeof(g_pigshell_traps[0]);

static struct compound_cmd_traps_ctx g_pigshell_pigsty_traps[] = {
    { "ld ",   pigsty_ld_cmdtrap    },
    { "ls",    pigsty_ls_cmdtrap    },
    { "rm ",   pigsty_rm_cmdtrap    },
    { "clear", pigsty_clear_cmdtrap }
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

    if (c == PIG_SHELL_BACKSPACE_KEY) {
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
    char history[PIG_MAX_HISTORY_NR][PIG_SHELL_CMDBUF_LEN];
    size_t h = 0, hc = 0;

    signal(SIGINT, shell_sigint_watchdog);
    signal(SIGTERM, shell_sigint_watchdog);

    memset(cmdbuf, 0, PIG_SHELL_CMDBUF_LEN);

    printf("%s", PIG_SHELL_PROMPT);
    fflush(stdout);

    while (!g_pig_shell_exit) {
        lchar = getch();

        if (lchar == PIG_SHELL_ESCAPE_KEY) {
            getch();
            switch ((lchar=getch())) {
                case PIG_SHELL_UP_KEY: // INFO(Rafael): Up/Down arrows.
                case PIG_SHELL_DOWN_KEY:
                    if (continue_line) {
                        printf("\n");
                    }
                    while (c > 0) {
                        printf("\b \b");
                        c--;
                    }
                    strncpy(cmdbuf, history[hc], PIG_SHELL_CMDBUF_LEN - 1);
                    printf("\r%s%s", PIG_SHELL_PROMPT, cmdbuf);
                    fflush(stdout);
                    c = strlen(cmdbuf);
                    lc = strlen(cmdbuf);
                    pc = 0;
                    continue_line = 0;
                    if (lchar == PIG_SHELL_UP_KEY) {
                        if (hc > 0) {
                            hc--;
                        }
                    } else {
                        if (hc < h) {
                            hc++;
                        }
                    }
                    break;

                case PIG_SHELL_LEFT_KEY: // INFO(Rafael): Left arrow.
                    if (lc > 0) {
                        lc--;
                        c--;
                        printf("\b");
                        fflush(stdout);
                    }
                    break;

                case PIG_SHELL_RIGHT_KEY: // INFO(Rafael): Right arrow.
                    if (cmdbuf[lc] != 0 && lc < PIG_SHELL_CMDBUF_LEN) {
                        lc++;
                        c++;
                        printf("\033[1C");
                        fflush(stdout);
                    }
                    break;

                case PIG_SHELL_END_KEY:  // INFO(Rafael): End key.
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

                case PIG_SHELL_DELETE_KEY: // INFO(Rafael): Delete key.
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
            if (lchar != '\r' && lchar != PIG_SHELL_BACKSPACE_KEY) {
                add_char_to_cmdbuf(cmdbuf, &c, lchar);
            }
            printf("\033[s");
            printf("\r%s%s", (continue_line == 0) ? PIG_SHELL_PROMPT : PIG_SHELL_CONTINUE, &cmdbuf[pc]);
            printf("\033[u");
            if (lchar != 126 && lchar != PIG_SHELL_BACKSPACE_KEY) {
                printf("\033[1C");
            }
            fflush(stdout);
        }

        if (g_pig_shell_exit) {
            printf("-- SIGNAL caught, bye! --\n");
            continue;
        }

        switch (lchar) {
            case PIG_SHELL_CTRL_C:
                if (continue_line) {
                    printf("\n");
                    goto shell_prompt_reset;
                } else {
                    g_pig_shell_exit = 1;
                }
                break;

            case PIG_SHELL_BACKSPACE_KEY:
                if (lc > 0) {
                    add_char_to_cmdbuf(cmdbuf, &c, PIG_SHELL_BACKSPACE_KEY);
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
                    if (strlen(cmdbuf) > 0) {
                        strncpy(history[h], cmdbuf, PIG_SHELL_CMDBUF_LEN - 1);
                        h = (h + 1) % PIG_MAX_HISTORY_NR;
                        hc = h - 1;
                    }
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
    del_pigsty_entry(g_pigsty_head);
    g_pigsty_tail = NULL;
    g_pigsty_head = NULL;
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
            return g_pigshell_traps[t].trap(cmd + ( strcmp(g_pigshell_traps[t].cmd, "[") == 0 ? 0 :
                                                              strlen(g_pigshell_traps[t].cmd) ) );
        }
        t++;
    }

    return -1;
}

static int append_pigsty_data(pigsty_entry_ctx *data) {
    pigsty_entry_ctx *dp, *np;
    int added = 0;

    if (data == NULL) {
        return 0;
    }

    np = NULL;

    if (g_pigsty_head != NULL) {
        for (dp = data; dp != NULL; dp = np) {
            np = dp->next;
            if (get_pigsty_entry_signature_name(dp->signature_name, g_pigsty_head) != NULL) {
                printf("WARN: a signature named as '%s' was previously load, this new one will be skipped.\n", dp->signature_name);
                rm_pigsty_entry(&data, dp->signature_name);
            } else {
                added++;
            }
        }
    } else {
        for (dp = data; dp != NULL; dp = dp->next) {
            added++;
        }
    }

    if (added == 0) {
        return 0;
    }

    if (g_pigsty_tail == NULL) {
        g_pigsty_head = data;
        g_pigsty_tail = get_pigsty_entry_tail(g_pigsty_head);
    } else {
        g_pigsty_tail->next = data;
        g_pigsty_tail = get_pigsty_entry_tail(data);
    }

    return added;
}

static int add_pigsty_cmdtrap(const char *cmd) {
    pigsty_entry_ctx *np = NULL, *p = NULL;
    int add_nr = 0;

    reset_compile_pigsty_line_ct();

    if (compile_pigsty_buffer(cmd) == 0) {
        return 1;
    }

    np = make_pigsty_data_from_loaded_data(NULL, cmd);

    if (np == NULL) {
        return 1;
    }

    add_nr = append_pigsty_data(np);

    switch (add_nr) {
        case 0:
            printf("no signatures were added. --\n");
            break;

        case 1:
            printf("1 signature was added. --\n");
            break;

        default:
            printf("%d signatures were added. --\n", add_nr);
            break;
    }

    return 0;
}

static int pigsty_ld_cmdtrap(const char *cmd) {
    const char *cp = cmd;
    char temp[255] = "";
    size_t t = 0;
    pigsty_entry_ctx *np = NULL;

    while (*cp != 0) {
        if (*cp == ',') {
            temp[t] = 0;
            np = load_pigsty_data_from_file(NULL, temp);
            append_pigsty_data(np);
            t = 0;
            temp[0] = 0;
        } else {
            if (t == 0 && *cp == ' ') {
                cp++;
                continue;
            }
            temp[t] = *cp;
            t = (t + 1) % sizeof(temp);
        }
        cp++;
    }

    if (temp[0] != 0) {
        temp[t] = 0;
        np = load_pigsty_data_from_file(NULL, temp);
        append_pigsty_data(np);
    }

    return 1;
}

static int pigsty_ls_cmdtrap(const char *cmd) {
    pigsty_entry_ctx *hp = NULL;
    size_t total_printed = 0;

    if (g_pigsty_head == NULL) {
        return 0;
    }

    printf("-- SIGNATURES\n\n");

    for (hp = g_pigsty_head; hp != NULL; hp = hp->next) {
        if (*cmd == 0) {
            printf("\t* %s\n", hp->signature_name);
            total_printed++;
        } else if (strstr(hp->signature_name, cmd+1) != NULL) {
            printf("\t* %s\n", hp->signature_name);
            total_printed++;
        }
    }

    if (total_printed == 0) {
        printf("No entries were found. --\n");
    } else {
        printf("\n%d %s --\n", total_printed, total_printed > 1 ? "entries were found." : "entry was found.");
    }

    return 0;
}

static int pigsty_rm_cmdtrap(const char *cmd) {
    const char *cp = cmd;
    char temp[255] = "";
    size_t t = 0;
    pigsty_entry_ctx *np = NULL;
    size_t rt = 0;

    while (*cp != 0) {
        if (*cp == ',') {
            temp[t] = 0;
            if (rm_pigsty_entry(&g_pigsty_head, temp) == 0) {
                printf("WARN: the signature '%s' was not found.\n", temp);
            } else {
                rt++;
            }
            t = 0;
            temp[0] = 0;
        } else {
            if (t == 0 && *cp == ' ') {
                cp++;
                continue;
            }
            temp[t] = *cp;
            t = (t + 1) % sizeof(temp);
        }
        cp++;
    }

    if (temp[0] != 0) {
        temp[t] = 0;
        if (rm_pigsty_entry(&g_pigsty_head, temp) == 0) {
            printf("WARN: the signature '%s' was not found.\n", temp);
        } else {
            rt++;
        }
    }

    if (rt > 0) {
        printf("%d %s --\n", rt, (rt > 1) ? "entries were removed." : "entry was removed.");
    }

    return 1;
}

static int pigsty_cmdtrap(const char *cmd) {
    size_t t;
    for (t = 0; t < g_pigshell_pigsty_traps_nr; t++) {
        if (strstr(cmd, g_pigshell_pigsty_traps[t].cmd) == cmd) {
            return g_pigshell_pigsty_traps[t].trap(cmd + strlen(g_pigshell_pigsty_traps[t].cmd));
        }
    }
    printf("Unknown sub-command: '%s'.\n", cmd);
    return 1;
}

static int pigsty_clear_cmdtrap(const char *cmd) {
    del_pigsty_entry(g_pigsty_head);
    g_pigsty_head = g_pigsty_tail = NULL;
    return 0;
}
