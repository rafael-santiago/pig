#include "run_pig_run.h"
#include "pktcraft.h"
#include "pcap_import.h"
#include "options.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef int (*pig_task_exec)();

int run_pig_run(int *was_subtask) {
    const char *option = NULL;
    struct pig_subtask {
        const char *name;
        pig_task_exec task;
    };
    pig_task_exec pig_task = pktcraft;
    struct pig_subtask subtasks[] = {
        { "pcap-import", pcap_import }
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

    if ((pig_task != pktcraft || get_option("help", NULL)) && was_subtask != NULL) {
        *was_subtask = 1;
    }

    return pig_task();
}
