/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "mkpkt.h"
#include "memory.h"
#include "lists.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include <string.h>

static void mk_ipv4_dgram(unsigned char *buf, size_t *buf_size, pigsty_conf_set_ctx *conf);

//static void mk_ipv6_dgram(unsigned char *buf, size_t *buf_size, pigsty_conf_set_ctx *conf);

static void mk_tcp_dgram(unsigned char **buf, size_t *buf_size, pigsty_conf_set_ctx *conf, const unsigned int src_addr[4], const unsigned int dst_addr[4], const int version);

static void mk_udp_dgram(unsigned char **buf, size_t *buf_size, pigsty_conf_set_ctx *conf, const unsigned int src_addr[4], const unsigned int dst_addr[4], const int version);

unsigned char *mk_ip_pkt(pigsty_conf_set_ctx *conf, size_t *pktsize) {
    unsigned char *retval = NULL;
    int version = 0;
    pigsty_field_ctx *ip_version = NULL, *protocol = NULL;
    ip_version = get_pigsty_conf_set_field(kIpv4_version, conf);
    size_t offset = 0;
    if (ip_version != NULL) {
        version = 4;
    }
    // else {
    //	ip_version = get_pigsty_conf_set_data(kIpv6_version);
    //  if (ip_version != NULL) {
    //          version = 6;
    //  }
    // }
    if (version == 4) {
        retval = (unsigned char *) pig_newseg(0xffff);
        mk_ipv4_dgram(retval, pktsize, conf);
    }
    return retval;
}

static void mk_ipv4_dgram(unsigned char *buf, size_t *buf_size, pigsty_conf_set_ctx *conf) {
    pigsty_conf_set_ctx *cp = NULL;
    struct ip4 iph;
    struct tcp tcph;
    struct udp udph;
    char *temp = NULL;
    unsigned int src_addr[4] = {0, 0, 0, 0};
    unsigned int dst_addr[4] = {0, 0, 0, 0};
    memset(&iph, 0, sizeof(struct ip4));
    for (cp = conf; cp != NULL; cp = cp->next) {
        switch (cp->field->index) {

            case kIpv4_version:
                iph.version = *(unsigned char *)cp->field->data;
                break;

            case kIpv4_ihl:
                iph.ihl = *(unsigned char *)cp->field->data;
                break;

            case kIpv4_tos:
                iph.tos = *(unsigned char *)cp->field->data;
                break;

            case kIpv4_tlen:
                iph.tlen = *(unsigned short *)cp->field->data;
                break;

            case kIpv4_id:
                iph.id = *(unsigned short *)cp->field->data;
                break;

            case kIpv4_flags:
                iph.flags_fragoff = (((unsigned short)*(unsigned char *)cp->field->data) << 13) | iph.flags_fragoff;
                break;

            case kIpv4_offset:
                iph.flags_fragoff = (iph.flags_fragoff << 13) | (((unsigned short)*(unsigned short *)cp->field->data) & 0x01fff);
                break;

            case kIpv4_ttl:
                iph.ttl = *(unsigned char *)cp->field->data;
                break;

            case kIpv4_protocol:
                iph.protocol = *(unsigned char *)cp->field->data;
                break;

            case kIpv4_checksum:
                iph.chsum = *(unsigned short *)cp->field->data;
                break;

            case kIpv4_src:
                iph.src = *(unsigned int *)cp->field->data;
                break;

            case kIpv4_dst:
                iph.dst = *(unsigned int *)cp->field->data;
                break;

            default:
                break;

        }
    }

    switch (iph.protocol) {

        case 6:
            src_addr[0] = iph.src;
            dst_addr[0] = iph.dst;
            mk_tcp_dgram(&iph.payload, &iph.payload_size, conf, src_addr, dst_addr, 4);
            break;

        case 17:
            src_addr[0] = iph.src;
            dst_addr[0] = iph.dst;
            mk_udp_dgram(&iph.payload, &iph.payload_size, conf, src_addr, dst_addr, 4);
            break;

    }

    iph.tlen = (4 *  iph.ihl) + iph.payload_size;
    iph.chsum = 0;
    iph.chsum = eval_ip4_chsum(iph);

    temp = mk_ip4_buffer(&iph, buf_size);
    memcpy(buf, temp, *buf_size % 0xffff);
    if (iph.payload != NULL) {
        free(iph.payload);
    }
    free(temp);
}

//static void mk_ipv6_dgram(unsigned char *buf, size_t *buf_size, pigsty_conf_set_ctx *conf) {
//}

static void mk_tcp_dgram(unsigned char **buf, size_t *buf_size, pigsty_conf_set_ctx *conf, const unsigned int src_addr[4], const unsigned int dst_addr[4], const int version) {
    pigsty_conf_set_ctx *cp = NULL;
    struct tcp tcph;
    unsigned char *buf_p = *buf;
    tcph.payload = NULL;
    for (cp = conf; cp != NULL; cp = cp->next) {
        switch (cp->field->index) {

            case kTcp_src:
                tcph.src = *(unsigned short *)cp->field->data;
                break;

            case kTcp_dst:
                tcph.dst = *(unsigned short *)cp->field->data;
                break;

            case kTcp_seq:
                tcph.seqno = *(unsigned long *)cp->field->data;
                break;

            case kTcp_ackno:
                tcph.ackno = *(unsigned long *)cp->field->data;
                break;

            case kTcp_size:
                tcph.len = *(unsigned char *)cp->field->data;
                break;

            case kTcp_reserv:
                tcph.reserv = *(unsigned char *)cp->field->data;
                break;

            case kTcp_urg:
                tcph.flags = ((*(unsigned char *)cp->field->data) << 5) | tcph.flags;
                break;

            case kTcp_ack:
                tcph.flags = ((*(unsigned char *)cp->field->data) << 4) | tcph.flags;
                break;

            case kTcp_psh:
                tcph.flags = ((*(unsigned char *)cp->field->data) << 3) | tcph.flags;
                break;

            case kTcp_rst:
                tcph.flags = ((*(unsigned char *)cp->field->data) << 2) | tcph.flags;
                break;

            case kTcp_syn:
                tcph.flags = ((*(unsigned char *)cp->field->data) << 1) | tcph.flags;
                break;

            case kTcp_fin:
                tcph.flags = (*(unsigned char *)cp->field->data) | tcph.flags;
                break;

            case kTcp_wsize:
                tcph.window = *(unsigned short *)cp->field->data;
                break;

            case kTcp_checksum:
                tcph.chsum = *(unsigned short *)cp->field->data;
                break;

            case kTcp_urgp:
                tcph.urgp = *(unsigned short *)cp->field->data;
                break;

            case kTcp_payload:
                tcph.payload = (unsigned char *)pig_newseg(cp->field->dsize);
                memcpy(tcph.payload, cp->field->data, cp->field->dsize);
                tcph.payload_size = cp->field->dsize;
                break;

            default:
                break;

        }
    }

    tcph.chsum = 0;
    switch (version) {

        case 4:
            tcph.chsum = eval_tcp_ip4_chsum(tcph, src_addr[0], dst_addr[0]);
            break;

    }

    buf_p = mk_tcp_buffer(&tcph, buf_size);
    if (tcph.payload != NULL) {
        free(tcph.payload);
    }
}

static void mk_udp_dgram(unsigned char **buf, size_t *buf_size, pigsty_conf_set_ctx *conf, const unsigned int src_addr[4], const unsigned int dst_addr[4], const int version) {
    pigsty_conf_set_ctx *cp = NULL;
    unsigned char *buf_p = *buf;
    struct udp udph;
    udph.payload = NULL;
    for (cp = conf; cp != NULL; cp = cp->next) {
        switch (cp->field->index) {

            case kUdp_src:
                udph.src = *(unsigned short *)cp->field->data;
                break;

            case kUdp_dst:
                udph.dst = *(unsigned short *)cp->field->data;
                break;

            case kUdp_size:
                udph.len = *(unsigned short *)cp->field->data;
                break;

            case kUdp_checksum:
                udph.chsum = *(unsigned short *)cp->field->data;
                break;

            case kUdp_payload:
                udph.payload = (unsigned char *)pig_newseg(cp->field->dsize);
                memcpy(udph.payload, cp->field->data, cp->field->dsize);
                udph.payload_size = cp->field->dsize;
                break;

            default:
                break;

        }
    }

    udph.chsum = 0;
    switch (version) {

        case 4:
            udph.chsum = eval_udp_chsum(udph, src_addr[0], dst_addr[0], udph.len);
            break;

    }

    buf_p = mk_udp_buffer(&udph, buf_size);
    if (udph.payload != NULL) {
        free(udph.payload);
    }
}

