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

static void mk_ipv4_dgram(unsigned char *buf, pigsty_conf_set_ctx *conf);

static void mk_ipv6_dgram(unsigned char *buf, pigsty_conf_set_ctx *conf);

static void mk_tcp_dgram(unsigned char *buf, pigsty_conf_set_ctx *conf);

static void mk_udp_dgram(unsigned char *buf, pigsty_conf_set_ctx *conf);

unsigned char *mk_ip_pkt(pigsty_conf_set_ctx *conf) {
    unsigned char *retval = NULL;    
    pigsty_field_ctx *ip_version = NULL, *protocol = NULL;
    ip_version = get_pigsty_conf_set_field(kIpv4_version, conf);
    size_t offset = 0;
    //if (ip_version == NULL) {
    //	ip_version = get_pigsty_conf_set_data(kIpv6_version);
    //}
    if (ip_version != NULL && ip_version->data != NULL) {
        retval = (unsigned char *) pig_newseg(0xffff);
        switch (*(int *)ip_version->data) {
    	    case kIpv4_version:
    		mk_ipv4_dgram(retval, conf);
    		protocol = get_pigsty_conf_set_field(kIpv4_protocol, conf);
    		break;
    		
    	    //case kIpv6_version:
    	    //	break;
        }
        if (protocol != NULL && protocol->data != NULL) {
    	    switch (*(int *)protocol->data) {
    		case 6:
    		    mk_tcp_dgram(&retval[offset], conf);
    		    break;
    		    
    		case 17:
    		    mk_udp_dgram(&retval[offset], conf);
    		    break;
    	    }
        }
    }
    return retval;
}

static void mk_ipv4_dgram(unsigned char *buf, pigsty_conf_set_ctx *conf) {
}

static void mk_ipv6_dgram(unsigned char *buf, pigsty_conf_set_ctx *conf) {

}

static void mk_tcp_dgram(unsigned char *buf, pigsty_conf_set_ctx *conf) {
}

static void mk_udp_dgram(unsigned char *buf, pigsty_conf_set_ctx *conf) {
}

