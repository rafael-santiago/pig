#include "memory.h"
#include <stdio.h>

void *pig_newseg(const size_t ssize) {
    void *seg = NULL;
    if (ssize == 0) {
        return NULL;
    }
    seg = malloc(ssize);
    if (seg == NULL) {
        printf("pig panic: no memory!\n");
        exit(1);
    }
    return seg;
}
