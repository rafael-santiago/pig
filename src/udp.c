#include "udp.h"
#include "memory.h"

void parse_udp_dgram(struct udp **hdr, const char *buf, size_t bsize) {
    struct udp *udp = *hdr;
    size_t p = 0;
    if (udp == NULL || buf == NULL || bsize == 0) {
	return;
    }
    udp->src = ((unsigned short)buf[0] << 8) | buf[1];
    udp->dst = ((unsigned short)buf[2] << 8) | buf[3];
    udp->len = ((unsigned short)buf[4] << 8) | buf[5];
    udp->chsum = ((unsigned short)buf[6] << 8) | buf[7];
    if (bsize > 8) {
	udp->payload_size = bsize - 8;
        udp->payload = (unsigned char *) pig_newseg(udp->payload_size);
	for (p = 0; p < udp->payload_size; p++) {
	    udp->payload[p] = buf[8 + p];
	}
    }
}

unsigned char *mk_udp_buffer(const struct udp *hdr, size_t *bsize) {
    unsigned char *retval = NULL;
    size_t p = 0;
    if (hdr == NULL || bsize == NULL) {
	return NULL;
    }
    *bsize = hdr->len;
    retval = (unsigned char *)pig_newseg(*bsize);
    retval[0] = (hdr->src & 0xff00) >> 8;
    retval[1] = hdr->src & 0x00ff;
    retval[2] = (hdr->dst & 0xff00) >> 8;
    retval[3] = hdr->dst & 0x00ff;
    retval[4] = (hdr->len & 0xff00) >> 8;
    retval[5] = hdr->len & 0x00ff;
    retval[6] = (hdr->chsum & 0xff00) >> 8;
    retval[7] = hdr->chsum & 0x00ff;
    for (p = 0; hdr->payload_size; p++) {
	retval[8 + p] = hdr->payload[p];
    }
    return retval;
}
