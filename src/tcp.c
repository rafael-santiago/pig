#include "tcp.h"
#include "memory.h"

void parse_tcp_dgram(struct tcp **hdr, const char *buf, size_t bsize) {
    struct tcp *tcp = *hdr;
    size_t p = 0;
    if (tcp == NULL || buf == NULL || bsize < 20) {
        return;
    }
    tcp->src = ((unsigned short)buf[ 0] << 8) | buf[1];
    tcp->dst = ((unsigned short)buf[ 2] << 8) | buf[3];
    tcp->seqno = ((unsigned int)buf[ 4] << 24) |
                 ((unsigned int)buf[ 5] << 16) |
                 ((unsigned int)buf[ 6] <<  8) | buf[7];
    tcp->ackno = ((unsigned int)buf[ 8] << 24) |
                 ((unsigned int)buf[ 9] << 16) |
                 ((unsigned int)buf[10] << 8)  | buf[11];
    tcp->len = (buf[12] & 0xf0) >> 4;
    tcp->reserv = ((buf[12] & 0x0f) << 2) | (buf[13] & 0xe0);
    tcp->flags = buf[13] & 0x3f;
    tcp->window = ((unsigned short)buf[14] << 8) | buf[15];
    tcp->chsum = ((unsigned short)buf[16] << 8) | buf[17];
    tcp->urgp = ((unsigned short)buf[18] << 8) | buf[19];
    tcp->payload = NULL;
    tcp->payload_size = 0;
    if(bsize > 20) {
        tcp->payload_size = bsize - 20;
        tcp->payload = (unsigned char *) pig_newseg(tcp->payload_size);
        for (p = 0; p < tcp->payload_size; p++) {
            tcp->payload[p] = buf[20 + p];
        }
    }
}

unsigned char *mk_tcp_buffer(const struct tcp *hdr, size_t *bsize) {
    unsigned char *retval = NULL;
    size_t p = 0;
    if (hdr == NULL || bsize == NULL) {
        return NULL;
    }
    *bsize = (4 * hdr->len) + hdr->payload_size;
    retval = (unsigned char *) pig_newseg(*bsize);
    retval[ 0] = (hdr->src & 0xff00) >> 8;
    retval[ 1] =  hdr->src & 0x00ff;
    retval[ 2] = (hdr->dst & 0xff00) >> 8;
    retval[ 3] =  hdr->dst & 0x00ff;
    retval[ 4] = (hdr->seqno & 0xff000000) >> 24;
    retval[ 5] = (hdr->seqno & 0x00ff0000) >> 16;
    retval[ 6] = (hdr->seqno & 0x0000ff00) >>  8;
    retval[ 7] =  hdr->seqno & 0x000000ff;
    retval[ 8] = (hdr->ackno & 0xff000000) >> 24;
    retval[ 9] = (hdr->ackno & 0x00ff0000) >> 16;
    retval[10] = (hdr->ackno & 0x0000ff00) >>  8;
    retval[11] =  hdr->ackno & 0x000000ff;
    retval[12] = (hdr->len & 0x0f) << 4 | (((hdr->reserv & 0x3f) & 0x3e) >> 2);
    retval[13] = ((hdr->reserv & 0x03) << 6) | hdr->flags;
    retval[14] = (hdr->window & 0xff00) >> 8;
    retval[15] =  hdr->window & 0x00ff;
    retval[16] = (hdr->chsum & 0xff00) >> 8;
    retval[17] =  hdr->chsum & 0x00ff;
    retval[18] = (hdr->urgp & 0xff00) >> 8;
    retval[19] =  hdr->urgp & 0x00ff;
    if (hdr->payload != NULL) {
        for (p = 0; p < hdr->payload_size; p++) {
            retval[20 + p] = hdr->payload[p];
        }
    }
    return retval;
}
