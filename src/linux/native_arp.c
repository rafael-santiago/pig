/*
 *                        Copyright (C) 2014, 2015 by Rafael Santiago
 *
 * This is free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "native_arp.h"
#include "rsk.h"
#include "../memory.h"
#include "../if.h"
#include "../eth.h"
#include "../arp.h"
#include "../ip.h"
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

char *get_mac_by_addr(in_addr_t addr, const char *loiface, const int max_tries) {
    struct ethernet_frame eth;
    struct arp arp;
    char *mac, *ip;
    unsigned char *mac_in_bytes, *rawpkt;
    size_t rawpkt_sz;
    int bytes_total;
    int sk;
    char buf[0xffff];
    int ntry = max_tries;
    unsigned short ether_type;
    struct arp *arp_reply;
    struct in_addr sin_addr;
    struct timeval tv;

    sin_addr.s_addr = addr;

    memset(&tv, 0, sizeof(tv));
    tv.tv_sec = 5;

    sk = lin_rsk_create(loiface);
    if (sk == -1) return NULL;

    setsockopt(sk, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sk, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    eth.payload = NULL;
    memset(&arp, 0, sizeof(struct arp));
    memset(eth.dest_hw_addr, 0xff, sizeof(eth.dest_hw_addr));
    mac = get_iface_mac(loiface);
    mac_in_bytes = mac2byte(mac, 6);
    memcpy(eth.src_hw_addr, mac_in_bytes, 6);
    free(mac);
    mac = NULL;
    free(mac_in_bytes);
    eth.ether_type = ETHER_TYPE_ARP;
    arp.hwtype = ARP_HW_TYPE_ETHERNET;
    arp.ptype = ARP_PROTO_TYPE_IP;
    arp.hw_addr_len = 6;
    arp.pt_addr_len = 4;
    arp.opcode = ARP_OPCODE_REQUEST;
    arp.src_hw_addr = (unsigned char *) pig_newseg(arp.hw_addr_len);
    memcpy(arp.src_hw_addr, eth.src_hw_addr, 6);

    ip = get_iface_ip(loiface);

    if (ip == NULL) {
        free(arp.src_hw_addr);
        return NULL;
    }

    arp.src_pt_addr = addr2byte(ip, 4);
    free(ip);
    arp.dest_hw_addr = (unsigned char *) pig_newseg(arp.hw_addr_len);
    memset(arp.dest_hw_addr, 0, arp.hw_addr_len);
    arp.dest_pt_addr = (unsigned char *)&addr;
    eth.payload = mk_arp_dgram(&eth.payload_size, arp);
    rawpkt = mk_ethernet_frame(&rawpkt_sz, eth);
    while (ntry-- > 0 && mac == NULL) {
        bytes_total = sendto(sk, rawpkt, rawpkt_sz, 0, NULL, 0);
        if (bytes_total > 0) {
            bytes_total = recvfrom(sk, buf, sizeof(buf), 0, NULL, 0);
            if (bytes_total > 0) {
                ether_type = (unsigned short) buf[12] << 8 | buf[13];
                if (ether_type == ETHER_TYPE_ARP) {
                    arp_reply = parse_arp_dgram((unsigned char *)&buf[14], bytes_total - 14);
                    if (arp_reply != NULL && arp_reply->opcode == ARP_OPCODE_REPLY) {
                        ip = (char *) pig_newseg(20);
                        sprintf(ip, "%d.%d.%d.%d", arp_reply->src_pt_addr[0],
                                                   arp_reply->src_pt_addr[1],
                                                   arp_reply->src_pt_addr[2],
                                                   arp_reply->src_pt_addr[3]);
                        if (strcmp(inet_ntoa(sin_addr), ip) == 0) {
                            mac = (char *) pig_newseg(20);
                            sprintf(mac, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", arp_reply->src_hw_addr[0],
                                                                          arp_reply->src_hw_addr[1],
                                                                          arp_reply->src_hw_addr[2],
                                                                          arp_reply->src_hw_addr[3],
                                                                          arp_reply->src_hw_addr[4],
                                                                          arp_reply->src_hw_addr[5]);
                        }
                        free(ip);
                    }
                    arp_header_free(arp_reply);
                    free(arp_reply);
                }
            }
        }
    }
    free(rawpkt);
    lin_rsk_close(sk);
    free(eth.payload);
    free(arp.src_hw_addr);
    free(arp.src_pt_addr);
    free(arp.dest_hw_addr);
    return mac;
}
