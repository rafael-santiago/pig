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
    if (strcmp(data, "south-american-ip") != 0 &&
        strcmp(data, "north-american-ip") != 0 &&
        strcmp(data, "european-ip")       != 0 &&
        strcmp(data, "asian-ip")          != 0) {
        retval = pig_newseg(sizeof(unsigned int));
        retval = to_ipv4(data);
        *dsize = sizeof(unsigned int);
    } else {
        *dsize = strlen(data);
        retval = pig_newseg(*dsize + 1);
        memset(retval, 0, *dsize + 1);
        memcpy(retval, data, *dsize);
    }
    return retval;
}
