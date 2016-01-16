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
#include "icmp.h"
#include "arp.h"
#include "mkrnd.h"
#include "pigsty.h"
#include <string.h>

static void mk_ipv4_dgram(unsigned char *buf, size_t *buf_size, pigsty_conf_set_ctx *conf, pig_target_addr_ctx *addrs);

//static void mk_ipv6_dgram(unsigned char *buf, size_t *buf_size, pigsty_conf_set_ctx *conf);

static void mk_usr_arp_dgram(unsigned char *buf, size_t *buf_size, pigsty_conf_set_ctx *conf, pig_target_addr_ctx *addrs);

static void mk_tcp_dgram(unsigned char **buf, size_t *buf_size, pigsty_conf_set_ctx *conf, const unsigned int src_addr[4], const unsigned int dst_addr[4], const int version);

static void mk_udp_dgram(unsigned char **buf, size_t *buf_size, pigsty_conf_set_ctx *conf, const unsigned int src_addr[4], const unsigned int dst_addr[4], const int version);

static void mk_icmp_dgram(unsigned char **buf, size_t *buf_size, pigsty_conf_set_ctx *conf, const int version);

static void mk_default_ipv4(struct ip4 *hdr);

static void mk_default_tcp(struct tcp *hdr);

static void mk_default_udp(struct udp *hdr);

unsigned char *mk_pkt(pigsty_conf_set_ctx *conf, pig_target_addr_ctx *addrs, size_t *pktsize) {
    unsigned char *retval = NULL;
    int version = 0;
    pigsty_field_ctx *fp = NULL, *protocol = NULL;
    fp = get_pigsty_conf_set_field(kIpv4_version, conf);
    size_t pkt_size = 0;
    if (fp != NULL) {
        version = 4;
    }
    // else {
    //  ip_version = get_pigsty_conf_set_data(kIpv6_version);
    //  if (ip_version != NULL) {
    //          version = 6;
    //  }
    // }
    switch (version) {
        case 4:
            retval = (unsigned char *) pig_newseg(0xffff);
            mk_ipv4_dgram(retval, pktsize, conf, addrs);
            break;

        default:
            if (is_arp_packet(conf)) {
                pkt_size = 8;
                fp = get_pigsty_conf_set_field(kArp_hwlen, conf);
                if (fp == NULL) {
                    pkt_size += 255; //  WARN(Santiago): It should never happen!!
                } else {
                    pkt_size += (*(unsigned char *)fp->data) * 2;
                }
                fp = get_pigsty_conf_set_field(kArp_plen, conf);
                if (fp == NULL) {
                    pkt_size += 255; //  WARN(Santiago): It should never happen too!!
                } else {
                    pkt_size += (*(unsigned char *)fp->data) * 2;
                }
                retval = (unsigned char *) pig_newseg(pkt_size);
                mk_usr_arp_dgram(retval, pktsize, conf, addrs);
            }
            break;
    }
    return retval;
}

static void mk_default_ipv4(struct ip4 *hdr) {
    hdr->version = 4;
    hdr->ihl = 5;
    hdr->tos = mk_rnd_u8();
    hdr->tlen = hdr->ihl * 4;
    hdr->id = mk_rnd_u16();
    hdr->flags_fragoff = 0x4000;
    hdr->ttl = 64;
    hdr->protocol = 0;
    hdr->chsum = 0;
    hdr->src = 0;
    hdr->dst = 0;
    hdr->payload_size = 0;
    hdr->payload = NULL;
}

static void mk_ipv4_dgram(unsigned char *buf, size_t *buf_size, pigsty_conf_set_ctx *conf, pig_target_addr_ctx *addrs) {
    pigsty_conf_set_ctx *cp = NULL;
    struct ip4 iph;
    struct tcp tcph;
    struct udp udph;
    char *temp = NULL;
    unsigned int src_addr[4] = {0, 0, 0, 0};
    unsigned int dst_addr[4] = {0, 0, 0, 0};
    size_t addrs_count = 0, addr_index = 0;

    memset(&iph, 0, sizeof(struct ip4));
    mk_default_ipv4(&iph);
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
                if (cp->field->data != NULL && cp->field->dsize > 4) {
                    if (strcmp(cp->field->data, "european-ip") == 0) {
                        iph.src = mk_rnd_european_ipv4();
                    } else if (strcmp(cp->field->data, "asian-ip") == 0) {
                        iph.src = mk_rnd_asian_ipv4();
                    } else if (strcmp(cp->field->data, "south-american-ip") == 0) {
                        iph.src = mk_rnd_south_american_ipv4();
                    } else if (strcmp(cp->field->data, "north-american-ip") == 0) {
                        iph.src = mk_rnd_north_american_ipv4();
                    } else if (strcmp(cp->field->data, "user-defined-ip") == 0) {
                        addrs_count = get_pig_target_addr_count(addrs);
                        addr_index = rand() % addrs_count;
                        iph.src = get_ipv4_pig_target_by_index(addr_index, addrs);
                    }
                } else {
                    iph.src = *(unsigned int *)cp->field->data;
                }
                break;

            case kIpv4_dst:
                if (cp->field->data != NULL && cp->field->dsize > 4) {
                    if (strcmp(cp->field->data, "european-ip") == 0) {
                        iph.dst = mk_rnd_european_ipv4();
                    } else if (strcmp(cp->field->data, "asian-ip") == 0) {
                        iph.dst = mk_rnd_asian_ipv4();
                    } else if (strcmp(cp->field->data, "south-american-ip") == 0) {
                        iph.dst = mk_rnd_south_american_ipv4();
                    } else if (strcmp(cp->field->data, "north-american-ip") == 0) {
                        iph.dst = mk_rnd_north_american_ipv4();
                    } else if (strcmp(cp->field->data, "user-defined-ip") == 0) {
                        addrs_count = get_pig_target_addr_count(addrs);
                        addr_index = rand() % addrs_count;
                        iph.dst = get_ipv4_pig_target_by_index(addr_index, addrs);
                    }
                } else {
                    iph.dst = *(unsigned int *)cp->field->data;
                }
                break;

            case kIpv4_payload:
                if (cp->field->data != NULL && cp->field->dsize > 0) {
                    iph.payload = (unsigned char *)cp->field->data;
                    iph.payload_size = cp->field->dsize;
                }
                break;

            default:
                break;

        }
    }

    switch (iph.protocol) {

        case 1:
            mk_icmp_dgram(&iph.payload, &iph.payload_size, conf, 4);
            break;

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

static void mk_usr_arp_dgram(unsigned char *buf, size_t *buf_size, pigsty_conf_set_ctx *conf, pig_target_addr_ctx *addrs) {
    pigsty_conf_set_ctx *cp = NULL;
    pigsty_field_ctx *fp = NULL;
    struct arp arph;
    arph.hw_addr_len = 0;
    arph.pt_addr_len = 0;
    arph.src_hw_addr = NULL;
    arph.dest_hw_addr = NULL;
    arph.src_pt_addr = NULL;
    arph.dest_pt_addr = NULL;
    for (cp = conf; cp != NULL; cp = cp->next) {
        switch (cp->field->index) {

            case kArp_hwtype:
                arph.hwtype = *(unsigned short *)cp->field->data;
                break;

            case kArp_ptype:
                arph.ptype = *(unsigned short *)cp->field->data;
                break;

            case kArp_hwlen:
                arph.hw_addr_len = *(unsigned char *)cp->field->data;
                fp = get_pigsty_conf_set_field(kArp_hwsrc, conf);
                if (fp != NULL) {
                    if (fp->dsize != arph.hw_addr_len) {
                        arph.hw_addr_len = fp->dsize;
                    }
                }
                break;

            case kArp_plen:
                arph.pt_addr_len = *(unsigned char *)cp->field->data;
                fp = get_pigsty_conf_set_field(kArp_psrc, conf);
                if (fp != NULL) {
                    if (fp->dsize != arph.pt_addr_len) {
                        arph.pt_addr_len = fp->dsize;
                    }
                }
                break;

            case kArp_opcode:
                arph.opcode = *(unsigned short *)cp->field->data;
                break;

            case kArp_hwsrc:
                arph.src_hw_addr = (unsigned char *) pig_newseg(cp->field->dsize);
                memcpy(arph.src_hw_addr, cp->field->data, cp->field->dsize);
                break;

            case kArp_psrc:
                arph.src_pt_addr = (unsigned char *) pig_newseg(cp->field->dsize);
                memcpy(arph.src_pt_addr, cp->field->data, cp->field->dsize);
                break;

            case kArp_hwdst:
                arph.dest_hw_addr = (unsigned char *) pig_newseg(cp->field->dsize);
                memcpy(arph.dest_hw_addr, cp->field->data, cp->field->dsize);
                break;

            case kArp_pdst:
                arph.dest_pt_addr = (unsigned char *) pig_newseg(cp->field->dsize);
                memcpy(arph.dest_pt_addr, cp->field->data, cp->field->dsize);
                break;

            default:
                break;

        }
    }
    free(arph.src_hw_addr);
    free(arph.dest_hw_addr);
    free(arph.src_pt_addr);
    free(arph.dest_pt_addr);
}

static void mk_default_tcp(struct tcp *hdr) {
    do {
        hdr->src = mk_rnd_u16();
    } while (hdr->src == 0);
    do {
        hdr->dst = mk_rnd_u16();
    } while (hdr->dst == 0);
    hdr->seqno = mk_rnd_u16();
    hdr->ackno = mk_rnd_u16();
    hdr->len = 5;
    hdr->reserv = mk_rnd_u6();
    hdr->flags = mk_rnd_u6();
    hdr->window = mk_rnd_u16();
    hdr->chsum = 0;
    hdr->urgp = mk_rnd_u16();
    hdr->payload_size = 0;
    hdr->payload = NULL;
}

static void mk_tcp_dgram(unsigned char **buf, size_t *buf_size, pigsty_conf_set_ctx *conf, const unsigned int src_addr[4], const unsigned int dst_addr[4], const int version) {
    pigsty_conf_set_ctx *cp = NULL;
    struct tcp tcph;
    memset(&tcph, 0, sizeof(struct tcp));
    mk_default_tcp(&tcph);
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

    if (tcph.chsum == 0) {
        switch (version) {

            case 4:
                tcph.chsum = eval_tcp_ip4_chsum(tcph, src_addr[0], dst_addr[0]);
                break;

        }
    }

    (*buf) = mk_tcp_buffer(&tcph, buf_size);
    if (tcph.payload != NULL) {
        free(tcph.payload);
    }
}

static void mk_default_udp(struct udp *hdr) {
    do {
        hdr->src = mk_rnd_u16();
    } while (hdr->src == 0);
    do {
        hdr->dst = mk_rnd_u16();
    } while (hdr->dst == 0);
    hdr->len = 8;
    hdr->chsum = 0;
    hdr->payload = NULL;
    hdr->payload_size = 0;
}

static void mk_udp_dgram(unsigned char **buf, size_t *buf_size, pigsty_conf_set_ctx *conf, const unsigned int src_addr[4], const unsigned int dst_addr[4], const int version) {
    pigsty_conf_set_ctx *cp = NULL;
    struct udp udph;
    memset(&udph, 0, sizeof(struct udp));
    mk_default_udp(&udph);
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
                udph.len += udph.payload_size;
                break;

            default:
                break;

        }
    }

    if (udph.chsum == 0) {
        switch (version) {

            case 4:
                udph.chsum = eval_udp_chsum(udph, src_addr[0], dst_addr[0], udph.len);
                break;

        }
    }

    (*buf) = mk_udp_buffer(&udph, buf_size);
    if (udph.payload != NULL) {
        free(udph.payload);
    }
}

static void mk_icmp_dgram(unsigned char **buf, size_t *buf_size, pigsty_conf_set_ctx *conf, const int version) {
    struct icmp icmph;
    pigsty_conf_set_ctx *cp = NULL;
    memset(&icmph, 0, sizeof(icmph));
    for (cp = conf; cp != NULL; cp = cp->next) {
        switch (cp->field->index) {

            case kIcmp_type:
                icmph.type = *(unsigned char *)cp->field->data;
                break;

            case kIcmp_code:
                icmph.code = *(unsigned char *)cp->field->data;
                break;

            case kIcmp_checksum:
                icmph.chsum = *(unsigned short *)cp->field->data;
                break;

            case kIcmp_payload:
                icmph.payload = (unsigned char *)pig_newseg(cp->field->dsize);
                memcpy(icmph.payload, cp->field->data, cp->field->dsize);
                icmph.payload_size = cp->field->dsize;
                break;

            default:
                break;

        }
    }

    if (icmph.chsum == 0) {
        switch (version) {

            case 4:
                icmph.chsum = eval_icmp_chsum(icmph);
                break;

        }
    }

    (*buf) = mk_icmp_buffer(&icmph, buf_size);
    if (icmph.payload != NULL) {
        free(icmph.payload);
    }
}
