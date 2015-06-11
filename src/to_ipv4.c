#include "to_ipv4.h"
#include "memory.h"
#include <string.h>

unsigned int *to_ipv4(const char *data) {
    unsigned int *retval = NULL;
    const char *dp = NULL;
    char oct[20];
    size_t o = 0;
    if (data == NULL) {
        return NULL;
    }
    retval = (unsigned int *) pig_newseg(sizeof(unsigned  int));
    *retval = 0;
    memset(oct, 0, sizeof(oct));
    for (dp = data; *dp != 0; dp++) {
        if (*dp == '.' || *(dp + 1) == 0) {
            if (*(dp + 1) == 0) {
                oct[o] = *dp;
            }
            *retval = ((*retval) << 8) | atoi(oct);
            o = 0;
            memset(oct, 0, sizeof(oct));
        } else {
            oct[o] = *dp;
            o = (o + 1) % sizeof(oct);
        }
    }
    return retval;
}
