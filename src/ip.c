#include "ip.h"
#include "memory.h"
#include <string.h>

void parse_ip4_dgram(struct ip4 **hdr, const char *buf, size_t bsize) {
    struct ip4 *ip = NULL;
    size_t payload_offset = 0;
    if (hdr == NULL || *hdr == NULL || buf == NULL) {
        return;
    }
    ip = *hdr;
    if (bsize < 1) {
        return;
    }
    ip->version = (buf[0] & 0xf0) >> 4;
    ip->ihl = buf[0] & 0x0f;
    if (bsize < ip->ihl * 4) {
        memset(ip, 0, sizeof(struct ip4));
        return;
    }
    ip->tos = buf[1];
    ip->tlen = ((unsigned short)buf[2] << 8) | buf[3];
    ip->id = ((unsigned short)buf[4] << 8) | buf[5];
    ip->flags_fragoff = ((unsigned short)buf[6]) << 8 | buf[7];
    ip->ttl = buf[8];
    ip->protocol = buf[9];
    ip->chsum = ((unsigned short)buf[10] << 8) | buf[11];
    ip->src = ((unsigned int)buf[12] << 24) |
              ((unsigned int)buf[13] << 16) |
              ((unsigned int)buf[14] <<  8) | buf[15];
    ip->dst = ((unsigned int)buf[16] << 24) |
              ((unsigned int)buf[17] << 16) |
              ((unsigned int)buf[18] <<  8) | buf[19];
    payload_offset = (ip->ihl * 4);
    if (payload_offset < bsize) {
        ip->payload = (unsigned char *) pig_newseg(payload_offset + 1);
        memcpy(ip->payload, &buf[payload_offset], bsize - ip->tlen);
    }
}