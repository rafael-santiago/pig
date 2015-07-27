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
#include "ip.h"
#include "lists.h"
#include "linux/native_arp.h"
#include <string.h>

#define PIG_ARP_TRIES_NR 2

static void fill_up_mac_addresses(struct ethernet_frame *eth, const struct ip4 iph, pig_hwaddr_ctx **hwaddr, const unsigned char *gw_hwaddr, const char *loiface) {
    unsigned int nt_addr[4] = { 0, 0, 0, 0 };
    pig_hwaddr_ctx *hwa_p = (*hwaddr);
    unsigned char *mac = NULL;
    in_addr_t addr;
    //  Getting the src MAC address.
    nt_addr[0] = iph.src;
    mac = get_ph_addr_from_pig_hwaddr(nt_addr, hwa_p);
    if (mac == NULL) {
        addr = htonl(iph.src);
        mac = get_mac_by_addr(addr, loiface, PIG_ARP_TRIES_NR);
        if (mac != NULL) {
            hwa_p = add_hwaddr_to_pig_hwaddr(hwa_p, mac, nt_addr, 4);
            free(mac);
            hwa_p = get_pig_hwaddr_tail(hwa_p);
            if (hwa_p != NULL) {
                mac = &hwa_p->ph_addr[0];
            }
        }
    }
    if (mac == NULL) {
        //  WARN(Santiago): using the gateway's physical MAC.
        mac = (unsigned char *)gw_hwaddr;
    }
    memcpy(eth->src_hw_addr, mac, sizeof(eth->src_hw_addr));
    //  Now, getting the dest MAC address.
    nt_addr[0] = iph.dst;
    mac = get_ph_addr_from_pig_hwaddr(nt_addr, hwa_p);
    if (mac == NULL) {
        addr = htonl(iph.dst);
        mac = get_mac_by_addr(addr, loiface, PIG_ARP_TRIES_NR);
        if (mac != NULL) {
            hwa_p = add_hwaddr_to_pig_hwaddr(hwa_p, mac, nt_addr, 4);
            free(mac);
            hwa_p = get_pig_hwaddr_tail(hwa_p);
            if (hwa_p != NULL) {
                mac = &hwa_p->ph_addr[0];
            }
        }
    }
    if (mac == NULL) {
        //  WARN(Santiago): using the gateway's physical MAC.
        mac = (unsigned char *)gw_hwaddr;
    }
    memcpy(eth->dest_hw_addr, mac, sizeof(eth->dest_hw_addr));
}

int oink(const pigsty_entry_ctx *signature, pig_hwaddr_ctx **hwaddr, const pig_target_addr_ctx *addrs, const int sockfd, const unsigned char *gw_hwaddr, const char *loiface) {
    unsigned char *packet = NULL;
    struct ethernet_frame eth;
    struct ip4 iph, *iph_p = &iph;
    size_t packet_size = 0;
    int retval = -1;
    eth.payload = mk_ip_pkt(signature->conf, (pig_target_addr_ctx *)addrs, &eth.payload_size);
    parse_ip4_dgram(&iph_p, eth.payload, eth.payload_size);
    eth.ether_type = ETHER_TYPE_IP;
    fill_up_mac_addresses(&eth, iph, hwaddr, gw_hwaddr, loiface);
    if (iph.payload != NULL) {
        free(iph.payload);
    }
    packet = mk_ethernet_frame(&packet_size, eth);
    free(eth.payload);
    if (packet != NULL) {
        retval = inject(packet, packet_size, sockfd);
        free(packet);
    }
    return retval;
}

//
//  TODO(Santiago): What is lacking...
//
//      - add these new options: --gateway=<ip-address> --lo-iface=<interface-name>.
//      - write code for gateway's mac address discoverying.
//      - rewrite the send function in rsk module in order to inject the packet from l1 to l7.
//
