/*                                                                                                                                                                                                                 
 *                                Copyright (C) 2015 by Rafael Santiago                                                                                                                                            
 *                                                                                                                                                                                                                 
 * This is a free software. You can redistribute it and/or modify under                                                                                                                                            
 * the terms of the GNU General Public License version 2.
 *
 */
#include "tcp.h"
#include "memory.h"

void parse_tcp_dgram(struct tcp **hdr, const unsigned char *buf, size_t bsize) {
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

unsigned short eval_tcp_ip4_chsum(const struct tcp hdr, const unsigned int src_addr, const unsigned int dst_addr) {
    struct ip_pseudo_hdr {
        unsigned int src;
        unsigned int dst;
        //WARN(Santiago): Here should go just another dummy ZERO.... let's skip this....
        unsigned char next_hdr;
        unsigned short payload_len;
    };
    unsigned char *stream_buf = NULL;
    int retval = 0;
    size_t p = 0;
    unsigned char hi = 0, lo = 0;
    struct ip_pseudo_hdr ipp_hdr;
    ipp_hdr.src = src_addr;
    ipp_hdr.dst = dst_addr;
    //  WARN(Santiago): Here in this implementation I am using the
    //                  payload field from tcp structure to save
    //                  the tcp option too. So,
    //                      ((4 * tcp_len) + payload_size)
    //                  could be a wrong calculation in some cases.
    //                  Due to it a better choice is use the default
    //                                              tcp header size.
    ipp_hdr.payload_len = 20 + hdr.payload_size;
    ipp_hdr.next_hdr = 6;
    retval += (ipp_hdr.src >> 16);
    retval += (ipp_hdr.src & 0x0000ffff);
    retval += (ipp_hdr.dst >> 16);
    retval += (ipp_hdr.dst & 0x0000ffff);
    retval += ipp_hdr.next_hdr;
    retval += ipp_hdr.payload_len;

    retval += hdr.src;
    retval += hdr.dst;
    retval += (hdr.seqno >> 16);
    retval += hdr.seqno & 0x0000ffff;
    retval += (hdr.ackno >> 16);
    retval += hdr.ackno & 0x0000ffff;
    retval += (((unsigned short)hdr.len << 12) | ((unsigned short)hdr.reserv << 6) | ((unsigned short)hdr.flags));
    retval += hdr.window;
    retval += hdr.chsum;
    retval += hdr.urgp;
    if (hdr.payload_size > 0 && hdr.payload != NULL) {
        p = 0;
        while (p < hdr.payload_size) {
            hi = hdr.payload[p++];
            lo = 0;
            if (p < hdr.payload_size) {
                lo = hdr.payload[p++];
            }
            retval += (((unsigned short) hi << 8) | lo);
        }
    }
    while (retval >> 16) {
        retval = (retval >> 16) + (retval & 0x0000ffff);
    }
    return (unsigned short)(~retval);
}
