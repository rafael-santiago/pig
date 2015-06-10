#ifndef _PIG_LINUX_RSK_H
#define _PIG_LINUX_RSK_H 1

#include <stdlib.h>

int lin_rsk_create();

void lin_rsk_close(const int sockfd);

int lin_rsk_sendto(const char *buffer, size_t buffer_size, const int sockfd);

#endif
