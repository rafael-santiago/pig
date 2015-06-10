/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "oink.h"
#include "sock.h"
#include "mkpkt.h"

int oink(const pigsty_entry_ctx *signature, const int sockfd) {
    unsigned char *packet = NULL;
    size_t packet_size = 0;
    int retval = -1;
    packet = mk_ip_pkt(signature->conf, &packet_size);
    if (packet != NULL) {
        retval = inject(packet, packet_size, sockfd);
        free(packet);
    }
    return retval;
}