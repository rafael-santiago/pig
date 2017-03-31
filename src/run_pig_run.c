/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "run_pig_run.h"
#include "pktcraft.h"
#include "pcap_import.h"
#include "shell.h"
#include "options.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef int (*pig_task_exec)(void);

int run_pig_run(void) {
    const char *option = NULL;
    struct pig_subtask {
        const char *name;
        pig_task_exec task;
    };
    pig_task_exec pig_task = pktcraft;
    struct pig_subtask subtasks[] = {
        { "pcap-import", pcap_import },
        { "shell", shell }
    };
    size_t subtasks_nr = sizeof(subtasks) / sizeof(subtasks[0]);
    size_t s = 0;

    option = get_option("sub-task", NULL);

    if (option != NULL) {
        while (s < subtasks_nr && pig_task == pktcraft) {
            if (strcmp(option, subtasks[s].name) == 0) {
                pig_task = subtasks[s].task;
            }
            s++;
        }

        if (pig_task == pktcraft) {
            printf("pig ERROR: sub-task \"%s\" is unknown.\n", option);
            return 1;
        }
    }

    return pig_task();
}
