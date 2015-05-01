#ifndef _PIG_TO_VOIDP_H
#define _PIG_TO_VOIDP_H 1

#include <stdlib.h>

void *int_to_voidp(const char *data, size_t *dsize);

void *str_to_voidp(const char *data, size_t *dsize);

void *ipv4_to_voidp(const char *data, size_t *dsize);

#endif
