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
#include "eth.h"
#include "arp.h"
#include "ip.h"
#include "if.h"
#include "lists.h"
#include "linux/native_arp.h"
#include <string.h>

#define PIG_ARP_TRIES_NR 1

#define pig_get_net_mask_from_addr(a, m) ( ( (a) & (m) ) )

static void fill_up_mac_addresses(struct ethernet_frame *eth, const struct ip4 iph, pig_hwaddr_ctx **hwaddr, const unsigned char *gw_hwaddr, const unsigned int nt_mask[4], const char *loiface);

static int should_route(const unsigned int addr[4], const unsigned int nt_mask[4], const char *loiface);

static int is_lopkt(const char *datagram, const size_t datagram_sz);

static int is_lopkt(const char *datagram, const size_t datagram_sz) {
    int retval = 0;
    unsigned int ip4_addr = 0;
    if (datagram != NULL && datagram_sz >= 20) {
        switch (((*datagram) & 0xf0) >> 4) {
            case 4:
                ip4_addr = (((unsigned int) datagram[12]) << 24) |
                           (((unsigned int) datagram[13]) << 16) |
                           (((unsigned int) datagram[14]) <<  8) |
                           ((unsigned int) datagram[15]);
                retval = ((ip4_addr & 0x7fffffff) == ip4_addr);
                if (retval == 0) {
                    ip4_addr = (((unsigned int) datagram[16]) << 24) |
                               (((unsigned int) datagram[17]) << 16) |
                               (((unsigned int) datagram[18]) <<  8) |
                               ((unsigned int) datagram[19]);
                }
                retval = ((ip4_addr & 0x7fffffff) == ip4_addr);
                break;

//            case 6:
//                break;
        }
    }
    return retval;
}

static int should_route(const unsigned int addr[4], const unsigned int nt_mask[4], const char *loiface) {
    static unsigned int lo_addr[4] = { 0, 0, 0, 0 };
    char *temp = NULL;
    if (lo_addr[0] == 0 && lo_addr[1] == 0 && lo_addr[2] == 0 && lo_addr[3] == 0) {
        temp = get_iface_ip(loiface);
        if (temp != NULL) {
            if (*temp != 0) {
                //  WARN(Santiago): until now IPv4 only.
                lo_addr[0] = htonl(inet_addr(temp));
            }
            free(temp);
        }
    }
    return !((pig_get_net_mask_from_addr(addr[0], nt_mask[0]) == pig_get_net_mask_from_addr(lo_addr[0], nt_mask[0])) &&
             (pig_get_net_mask_from_addr(addr[1], nt_mask[1]) == pig_get_net_mask_from_addr(lo_addr[1], nt_mask[1])) &&
             (pig_get_net_mask_from_addr(addr[2], nt_mask[2]) == pig_get_net_mask_from_addr(lo_addr[2], nt_mask[2])) &&
             (pig_get_net_mask_from_addr(addr[3], nt_mask[3]) == pig_get_net_mask_from_addr(lo_addr[3], nt_mask[3])));
}

static void fill_up_mac_addresses(struct ethernet_frame *eth, const struct ip4 iph, pig_hwaddr_ctx **hwaddr, const unsigned char *gw_hwaddr, const unsigned int nt_mask[4], const char *loiface) {
    unsigned int nt_addr[4] = { 0, 0, 0, 0 };
    pig_hwaddr_ctx *hwa_p = (*hwaddr);
    unsigned char *mac = NULL, *temp = NULL;
    in_addr_t addr;
    //  Getting the src MAC address.
    nt_addr[0] = iph.src;
    if (!should_route(nt_addr, nt_mask, loiface)) {
        mac = get_ph_addr_from_pig_hwaddr(nt_addr, hwa_p);
        if (mac == NULL) {
            addr = htonl(iph.src);
            temp = get_mac_by_addr(addr, loiface, PIG_ARP_TRIES_NR);
            if (temp != NULL) {
                mac = mac2byte(temp, strlen(temp));
                free(temp);
                hwa_p = add_hwaddr_to_pig_hwaddr(hwa_p, mac, nt_addr, 4);
                free(mac);
                hwa_p = get_pig_hwaddr_tail(hwa_p);
                if (hwa_p != NULL) {
                    mac = &hwa_p->ph_addr[0];
                }
            }
        }
    }
    if (mac == NULL) {
        //  WARN(Santiago): using the gateway's physical MAC.
        mac = (unsigned char *)gw_hwaddr;
    }
    memcpy(eth->src_hw_addr, mac, sizeof(eth->src_hw_addr));
    mac = NULL;
    //  Now, getting the dest MAC address.
    nt_addr[0] = iph.dst;
    if (!should_route(nt_addr, nt_mask, loiface)) {
        mac = get_ph_addr_from_pig_hwaddr(nt_addr, hwa_p);
        if (mac == NULL) {
            addr = htonl(iph.dst);
            temp = get_mac_by_addr(addr, loiface, PIG_ARP_TRIES_NR);
            if (temp != NULL) {
                mac = mac2byte(temp, strlen(temp));
                free(temp);
                hwa_p = add_hwaddr_to_pig_hwaddr(hwa_p, mac, nt_addr, 4);
                free(mac);
                hwa_p = get_pig_hwaddr_tail(hwa_p);
                if (hwa_p != NULL) {
                    mac = &hwa_p->ph_addr[0];
                }
            }
        }
    }
    if (mac == NULL) {
        //  WARN(Santiago): using the gateway's physical MAC.
        mac = (unsigned char *)gw_hwaddr;
    }
    memcpy(eth->dest_hw_addr, mac, 6);
}

int oink(const pigsty_entry_ctx *signature, pig_hwaddr_ctx **hwaddr, const pig_target_addr_ctx *addrs, const int sockfd, const unsigned char *gw_hwaddr, const unsigned int nt_mask[4], const char *loiface) {
    unsigned char *packet = NULL;
    struct ethernet_frame eth;
    struct ip4 iph, *iph_p = &iph;
    size_t packet_size = 0;
    int retval = -1;
    int sockfd_lo = -1;
    eth.payload = mk_ip_pkt(signature->conf, (pig_target_addr_ctx *)addrs, &eth.payload_size);
    if (!is_lopkt(eth.payload, eth.payload_size)) {
        parse_ip4_dgram(&iph_p, eth.payload, eth.payload_size);
        eth.ether_type = ETHER_TYPE_IP;
        fill_up_mac_addresses(&eth, iph, hwaddr, gw_hwaddr, nt_mask, loiface);
        if (iph.payload != NULL) {
            free(iph.payload);
        }
        packet = mk_ethernet_frame(&packet_size, eth);
        free(eth.payload);
        if (packet != NULL) {
            retval = inject(packet, packet_size, sockfd);
            free(packet);
        }
    } else {
        sockfd_lo = init_loopback_raw_socket();
        if (sockfd_lo != -1) {
            retval = inject_lo(eth.payload, eth.payload_size, sockfd_lo);
            deinit_raw_socket(sockfd_lo);
        }
        free(eth.payload);
    }
    return retval;
}
