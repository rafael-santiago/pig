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
#include "strglob.h"
#include "memory.h"
#include "pktcraft.h"
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

#define PIG_SHELL_ARGV_NR 1000

#define PIG_SHELL_ARGV_LEN 8192

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
    int match_exact;
    pigshell_cmdtrap trap;
};

static int shell_help(void);

static int shell_prompt(void);

static int g_pig_shell_exit = 0;

static char **g_pig_shell_argv = NULL;

static int g_pig_shell_argc = 0;

static pigsty_entry_ctx *g_pigsty_head = NULL, *g_pigsty_tail = NULL;

static void pig_shell_init(void);

static void pig_shell_deinit(void);

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

static int set_cmdtrap(const char *cmd);

static int unset_cmdtrap(const char *cmd);

static void pigshell_pack_options(void);

static char *get_next_cmdarg(const char *cmd, const char **next);

static int flood_cmdtrap(const char *cmd);

static int oink_cmdtrap(const char *cmd);

static struct compound_cmd_traps_ctx g_pigshell_traps[] = {
    { "[",       0, add_pigsty_cmdtrap },
    { "flood ",  0, flood_cmdtrap      },
    { "flood",   1, flood_cmdtrap      },
    { "oink ",   0, oink_cmdtrap       },
    { "oink",    1, oink_cmdtrap       },
    { "pigsty ", 0, pigsty_cmdtrap     },
    { "set ",    0, set_cmdtrap        },
    { "set",     1, set_cmdtrap        },
    { "unset ",  0, unset_cmdtrap      }
};

static size_t g_pigshell_traps_nr = sizeof(g_pigshell_traps) / sizeof(g_pigshell_traps[0]);

static struct compound_cmd_traps_ctx g_pigshell_pigsty_traps[] = {
    { "ld ",   0, pigsty_ld_cmdtrap    },
    { "ls ",   0, pigsty_ls_cmdtrap    },
    { "ls",    1, pigsty_ls_cmdtrap    },
    { "rm ",   0, pigsty_rm_cmdtrap    },
    { "clear", 0, pigsty_clear_cmdtrap }
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

    // CLUE(Rafael): Here sometimes to add is to erase.

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

    pig_shell_init();

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
                case PIG_SHELL_UP_KEY:
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

                case PIG_SHELL_LEFT_KEY:
                    if (lc > 0) {
                        lc--;
                        c--;
                        printf("\b");
                        fflush(stdout);
                    }
                    break;

                case PIG_SHELL_RIGHT_KEY:
                    if (cmdbuf[lc] != 0 && lc < PIG_SHELL_CMDBUF_LEN) {
                        lc++;
                        c++;
                        printf("\033[1C");
                        fflush(stdout);
                    }
                    break;

                case PIG_SHELL_END_KEY:
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

                case PIG_SHELL_DELETE_KEY:
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

    pig_shell_deinit();


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
static void pig_shell_init(void) {
    char **argv = get_argv();
    int argc = get_argc();

    g_pig_shell_argv = (char **) pig_newseg(sizeof(char *) * PIG_SHELL_ARGV_NR);

    for (g_pig_shell_argc = 0; g_pig_shell_argc < PIG_SHELL_ARGV_NR; g_pig_shell_argc++) {
        g_pig_shell_argv[g_pig_shell_argc] = (char *) pig_newseg(sizeof(char) * PIG_SHELL_ARGV_LEN);
    }

    for (g_pig_shell_argc = 0; g_pig_shell_argc < argc; g_pig_shell_argc++) {
        strncpy(g_pig_shell_argv[g_pig_shell_argc], argv[g_pig_shell_argc], PIG_SHELL_ARGV_LEN - 1);
    }

    /* INFO(Rafael): Those options were previously registered by the main() function. We do not have to
                     worry about option registering issues here. */
}

static void pig_shell_deinit(void) {
    if (g_pig_shell_argv != NULL) {
        register_options(0, NULL);

        for (g_pig_shell_argc = 0; g_pig_shell_argc < PIG_SHELL_ARGV_NR; g_pig_shell_argc++) {
            free(g_pig_shell_argv[g_pig_shell_argc]);
        }

        g_pig_shell_argc = 0;

        free(g_pig_shell_argv);
        g_pig_shell_argv = NULL;
    }
}

static int exec_compound_cmd(const char *cmd) {
    size_t t = 0;
    int matches = 0;

    while (t < g_pigshell_traps_nr) {
        if (g_pigshell_traps[t].trap != NULL) {
            matches = (!g_pigshell_traps[t].match_exact) ?
                        (strstr(cmd, g_pigshell_traps[t].cmd) == cmd) :
                        (strcmp(cmd, g_pigshell_traps[t].cmd) == 0);
            if (matches) {
                return g_pigshell_traps[t].trap(cmd + ( strcmp(g_pigshell_traps[t].cmd, "[") == 0 ? 0 :
                                                                  strlen(g_pigshell_traps[t].cmd) ) );
            }
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
    const char *cp = cmd, *next = NULL, *arg = NULL;
    size_t t = 0;
    pigsty_entry_ctx *np = NULL;

    arg = get_next_cmdarg(cp, &next);
    cp = next;

    while (arg != NULL) {
        np = load_pigsty_data_from_file(NULL, arg);
        append_pigsty_data(np);
        arg = get_next_cmdarg(cp, &next);
        cp = next;
    }

    return 0;
}

static int pigsty_ls_cmdtrap(const char *cmd) {
    pigsty_entry_ctx *hp = NULL;
    size_t total_printed = 0;
    const char *arg = NULL, *next = NULL, *cp = cmd;

    if (g_pigsty_head == NULL) {
        return 0;
    }

    printf("-- SIGNATURES\n\n");

    if (*cmd == 0) {
        for (hp = g_pigsty_head; hp != NULL; hp = hp->next) {
            if (*cmd == 0) {
                printf("\t* %s\n", hp->signature_name);
                total_printed++;
            }
        }
    } else {
        arg = get_next_cmdarg(cp, &next);
        cp = next;

        while (arg != NULL) {
            for (hp = g_pigsty_head; hp != NULL; hp = hp->next) {
                if (strglob(hp->signature_name, arg)) {
                    printf("\t* %s\n", hp->signature_name);
                    total_printed++;
                }
            }

            arg = get_next_cmdarg(cp, &next);
            cp = next;
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
    const char *cp = cmd, *next = NULL, *arg = NULL;
    size_t rt = 0, t;

    arg = get_next_cmdarg(cp, &next);
    cp = next;

    while (arg != NULL) {
        if ((t = rm_pigsty_entry(&g_pigsty_head, arg)) == 0) {
            printf("WARN: the signature '%s' was not found.\n", arg);
        } else {
            rt += t;
        }
        arg = get_next_cmdarg(cp, &next);
        cp = next;
    }

    if (rt > 0) {
        printf("%d %s --\n", rt, (rt > 1) ? "entries were removed." : "entry was removed.");
    }

    return 1;
}

static int pigsty_cmdtrap(const char *cmd) {
    size_t t;
    int matches = 0;

    for (t = 0; t < g_pigshell_pigsty_traps_nr; t++) {
        matches = (!g_pigshell_pigsty_traps[t].match_exact) ?
                    (strstr(cmd, g_pigshell_pigsty_traps[t].cmd) == cmd) :
                    (strcmp(cmd, g_pigshell_pigsty_traps[t].cmd) == 0);
        if (matches) {
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

static int set_cmdtrap(const char *cmd) {
    char option[255] = "", *op = NULL;
    char temp[255] = "";
    char data[255] = "";
    int a;
    const char *arg = NULL, *cp = cmd, *next = NULL;

    if (cmd == NULL) {
        return 1;
    }

    if (*cmd == 0) {
        for (a = 0; a < g_pig_shell_argc; a++) {
            printf("\t%s\n", g_pig_shell_argv[a]);
        }
        return 0;
    }

    arg = get_next_cmdarg(cp, &next);
    cp = next;

    while (arg != NULL) {
        sprintf(data, "--%s", arg);
        sprintf(option, "--%s", arg);
        op = strstr(option, "=");
        if (op != NULL) {
            *op = 0;
        }

        for (a = 0; a < g_pig_shell_argc; a++) {
            sprintf(temp, "%s", g_pig_shell_argv[a]);
            op = strstr(temp, "=");
            if (op != NULL) {
                *op = 0;
            }
            if (strcmp(temp, option) == 0) {
                goto set_cmdtrap_registering;
            }
        }

        g_pig_shell_argc = a + 1;

        set_cmdtrap_registering:
        strncpy(g_pig_shell_argv[a], data, PIG_SHELL_ARGV_LEN - 1);

        arg = get_next_cmdarg(cp, &next);
        cp = next;
    }

    register_options(g_pig_shell_argc, g_pig_shell_argv);

    return 0;
}

static int unset_cmdtrap(const char *cmd) {
    char option[255] = "";
    char temp[255] = "", *tp = NULL;
    int a;
    const char *arg = NULL, *next = NULL, *cp = cmd;
    int unset_nr = 0;

    if (cmd == NULL) {
        return 1;
    }

    arg = get_next_cmdarg(cp, &next);
    cp = next;

    while (arg != NULL) {

        sprintf(option, "--%s", arg);

        for (a = 0; a < g_pig_shell_argc; a++) {
            sprintf(temp, "%s", g_pig_shell_argv[a]);
            tp = strstr(temp, "=");

            if (tp != NULL) {
                *tp = 0;
            }

            if (strglob(temp, option)) {
                g_pig_shell_argv[a][0] = 0;
                unset_nr++;
            }
        }

        arg = get_next_cmdarg(cp, &next);
        cp = next;
    }

    if (unset_nr > 0) {
        pigshell_pack_options();
        register_options(g_pig_shell_argc, g_pig_shell_argv);
        return 0;
    }

    printf("WARN: option '%s' could not be unset because it does not exist.\n");

    return 1;
}

static void pigshell_pack_options(void) {
    int a;

    for (a = 0; a < g_pig_shell_argc; a++) {
        if (g_pig_shell_argv[a][0] == 0 && (a + 1) < PIG_SHELL_ARGV_NR) {
            strncpy(g_pig_shell_argv[a], g_pig_shell_argv[a+1], PIG_SHELL_ARGV_LEN - 1);
            a--;
            g_pig_shell_argc--;
        }
    }
}

static char *get_next_cmdarg(const char *cmd, const char **next) {
    const char *cp = cmd, *arg = NULL;
    static char curr_arg[255] = "";
    int sq = 0;

    if (cmd == NULL || *cmd == 0 || next == NULL) {
        return NULL;
    }

    arg = cp;

    while (*arg == ' ') {
        arg++;
    }

    while (*cp != ',' && *cp != 0) {
        if (*cp == '\"') {
            cp++;
            while (*cp != '"' && *cp != 0) {
                if (*cp == '\\') {
                    cp++;
                }
                cp++;
            }
        }
        cp++;
    }

    *next = cp + (*cp == ',');

    if (*arg == '"') {
        arg++;
        sq = 1;
    }

    memset(curr_arg, 0, sizeof(curr_arg));
    memcpy(curr_arg, arg, *next - arg - (*cp == ','));

    if (sq && curr_arg[strlen(curr_arg) - 1] == '\"') {
        curr_arg[strlen(curr_arg) - 1] = 0;
    }

    return &curr_arg[0];
}

static int flood_cmdtrap(const char *cmd) {
    struct pktcraft_options_ctx options;
    int exit_code = 0;
    const char *arg = NULL, *cp = NULL, *next = NULL;

    options.pigsty = g_pigsty_head;

    if (parse_pktcraft_options(&options) != 0) {
        return 1;
    }

    cp = cmd;
    arg = get_next_cmdarg(cp, &next);
    cp = next;

    while (arg != NULL) {
        if (verify_int(arg) == 0) {
            printf("ERROR: invalid number of times '%s'.\n", arg);
            return 1;
        }
        options.times_nr += atoi(arg);
        arg = get_next_cmdarg(cp, &next);
        cp = next;
    }

    signal(SIGINT, pktcrafter_sigint_watchdog);
    signal(SIGTERM, pktcrafter_sigint_watchdog);

    exit_code = exec_pktcraft(options);

    if (pktcraft_aborted()) {
        // INFO(Rafael): Avoiding users with impatient nervous hands... ;)
        printf("\nINFO: Your shell will come back within 3 secs...\n");
        sleep(3);
    } else if (exit_code == 0 && options.times_nr > 1) {
        printf("\n%d signatures sent. --\n", options.times_nr);
    }

    signal(SIGINT, shell_sigint_watchdog);
    signal(SIGTERM, shell_sigint_watchdog);

    return exit_code;
}

static int oink_cmdtrap(const char *cmd) {
    int exit_code = 1;
    const char *arg1 = NULL, *cp = NULL, *next = NULL, *arg2 = NULL, *temp = NULL;
    char mask[255] = "";
    struct pktcraft_options_ctx options;

    options.pigsty = g_pigsty_head;

    if (parse_pktcraft_options(&options) != 0) {
        return 1;
    }

    if (cmd != NULL && *cmd == 0) {
        printf("\n-- Sending a random signature...\n\n");

        options.single_test = "1";

        exit_code = exec_pktcraft(options);

        if (exit_code == 0) {
            printf("\n\n-- done.\n");
        }

        return exit_code;
    }

    cp = cmd;
    arg1 = get_next_cmdarg(cp, &next);
    cp = next;

    signal(SIGINT, pktcrafter_sigint_watchdog);
    signal(SIGTERM, pktcrafter_sigint_watchdog);

    while (arg1 != NULL) {
        strncpy(mask, arg1, sizeof(mask) - 1);
        options.globmask = &mask[0];

        arg2 = get_next_cmdarg(cp, &next);
        cp = next;

        if (arg2 != NULL && strcmp(arg2, "0") != 0 && verify_int(arg2)) {
            options.times_nr = atoi(arg2);
            temp = get_next_cmdarg(cp, &next);
            cp = next;
        } else {
            options.times_nr = 0;
            temp = arg2;
        }

        if (options.times_nr > 1) {
            printf("\n-- Sending signatures based on the pattern '%s' (%d for each found one)...\n\n", options.globmask, options.times_nr);
        } else {
            printf("\n-- Sending signatures based on the pattern '%s'...\n\n", options.globmask);
        }

        exit_code = exec_pktcraft(options);

        if (pktcraft_aborted()) {
            // INFO(Rafael): Avoiding users with impatient nervous hands... ;)
            printf("\nINFO: Your shell will come back within 3 secs...\n");
            sleep(3);
            temp = NULL;
        } else if (exit_code == 0) {
            printf("\ndone. --\n");
        }

        arg1 = temp;
    }

    signal(SIGINT, shell_sigint_watchdog);
    signal(SIGTERM, shell_sigint_watchdog);

    return exit_code;
}
