#include "to_voidp.h"
#include "memory.h"
#include "to_int.h"
#include "to_str.h"
#include "to_ipv4.h"
#include <string.h>

void *int_to_voidp(const char *data, size_t *dsize) {
    void *retval = NULL;
    if (data == NULL || dsize == NULL) {
        return NULL;
    }
    retval = pig_newseg(sizeof(int));
    *dsize = sizeof(int);
    *(int *)retval = to_int(data);
    return retval;
}

void *str_to_voidp(const char *data, size_t *dsize) {
    void *retval = NULL;
    if (data == NULL || dsize == NULL) {
        return NULL;
    }
    retval = pig_newseg(strlen(data));
    retval = to_str(data);
    *dsize = strlen(retval);
    return retval;
}

void *ipv4_to_voidp(const char *data, size_t *dsize) {
    void *retval = NULL;
    if (data == NULL || dsize == NULL) {
        return NULL;
    }
    retval = pig_newseg(sizeof(unsigned int));
    retval = to_ipv4(data);
    *dsize = sizeof(unsigned int);
    return retval;
}
