/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "../types.h"
#include "../pigsty.h"
#include "../to_int.h"
#include "../to_str.h"
#include "../to_ipv4.h"
#include "../lists.h"
#include "../ip.h"
#include "../udp.h"
#include "../tcp.h"
#include "../netmask.h"
#include <cutest.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int write_to_file(const char *filepath, const char *data) {
    FILE *fp = fopen(filepath, "wb");
    int retval = 0;
    size_t dsize = 0;
    if (fp == NULL) {
        return 0;
    }
    dsize = strlen(data);
    retval = (fwrite(data, dsize, 1, fp) > -1);
    fclose(fp);
    return retval;
}

CUTE_TEST_CASE(pigsty_file_parsing_tests)
    pigsty_entry_ctx *pigsty = NULL;
    char *test_pigsty = "[ ip.version = 4, ip.tos = 5, ip.src = 127.900.0.1 ]";  //  invalid ip octect.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    CUTE_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");

    test_pigsty = "[ ip.version = 4, ip.tos = 5, ip.src = 127.0.0.0.1 ]";  //  invalid ip with more octects than expected.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    CUTE_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");

    test_pigsty = "[ ip.version = 4x0, ip.tos = 5, ip.src = 127.0.0.1 ]";  //  invalid ip version.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    CUTE_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");


    test_pigsty = "[ ip.version = 0x00004, ip.tos = 5, ip.src = 127.0.0.1 ] [ip.version = 4, ip.tlen = 20a ]";  //  invalid ip version.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    CUTE_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");

    test_pigsty = "[ signature = \"valid signature\", ip.version = 4, ip.tos = 5, ip.src = 127.0.0.1 ]"; //  valid pigsty entry.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    CUTE_CHECK("pigsty == NULL", pigsty != NULL);
    CUTE_CHECK("pigsty->signature_name != valid signature", strcmp(pigsty->signature_name, "valid signature") == 0);
    CUTE_CHECK("pigsty->conf == NULL", pigsty->conf != NULL);
    CUTE_CHECK("pigsty->conf->field == NULL", pigsty->conf->field != NULL);
    CUTE_CHECK("pigsty->conf->field.index != kIpv4_version", pigsty->conf->field->index == kIpv4_version);
    CUTE_CHECK("pigsty->conf->next == NULL", pigsty->conf->next != NULL);
    CUTE_CHECK("pigsty->conf->next->field == NULL", pigsty->conf->next->field != NULL);
    CUTE_CHECK("pigsty->conf->next->field->index != kIpv4_tos", pigsty->conf->next->field->index == kIpv4_tos);
    CUTE_CHECK("pigsty->conf->next->next == NULL", pigsty->conf->next->next != NULL);
    CUTE_CHECK("pigsty->conf->next->next->field == NULL", pigsty->conf->next->next->field != NULL);
    CUTE_CHECK("pigsty->conf->next->next->field->index != kIpv4_src", pigsty->conf->next->next->field->index == kIpv4_src);
    CUTE_CHECK("pigsty->conf->next->next->next != NULL", pigsty->conf->next->next->next == NULL);
    remove("test.pigsty");
    del_pigsty_entry(pigsty);

CUTE_TEST_CASE_END

CUTE_TEST_CASE(to_int_tests)
    CUTE_CHECK("to_int() != 0", to_int(NULL) == 0);
    CUTE_CHECK("to_int() != 4", to_int("4") == 4);
    CUTE_CHECK("to_int() != 0xf", to_int("0xf") == 0xf);
    CUTE_CHECK("to_int() != 0x0f", to_int("0x0f") == 0xf);
    CUTE_CHECK("to_int() != 0xe0", to_int("0xe0") == 0xe0);
    CUTE_CHECK("to_int() == 0", to_int(NULL) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(to_str_tests)
    char *retval = NULL;
    CUTE_CHECK("to_str() != NULL", to_str(NULL) == NULL);
    retval = to_str("\"\\n\\r\\t\"");
    CUTE_CHECK("to_str() != \"\\n\\r\\t\"", strcmp(retval, "\n\r\t") == 0);
    free(retval);
    retval = to_str("\"r\\nr\\nn\\ne\\n\"");
    CUTE_CHECK("to_str() != \"r\\nr\\nn\\ne\\n\"", strcmp(retval, "r\nr\nn\ne\n") == 0);
    free(retval);
    retval = to_str("\"\x61\x62\x63\"");
    CUTE_CHECK("to_str() != \"abc\"", strcmp(retval, "abc") == 0);
    free(retval);
    retval = to_str("\"\x61\x62\x6362\"");
    CUTE_CHECK("to_str() != \"abb\"", strcmp(retval, "abb") == 0);
    free(retval);
    retval = to_str("\"\x9tab!\"");
    CUTE_CHECK("to_str() != \"\\ttab!\"", strcmp(retval, "\ttab!") == 0);
    free(retval);
    retval = to_str("\"well behaved string.\"");
    CUTE_CHECK("to_str() != \"well behaved string.\"", strcmp(retval, "well behaved string.") == 0);
    free(retval);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(to_ipv4_tests)
    unsigned int *retval = NULL;
    retval = to_ipv4(NULL);
    CUTE_CHECK("retval != NULL", retval == NULL);
    retval = to_ipv4("127.0.0.1");
    CUTE_CHECK("retval == NULL", retval != NULL);
    CUTE_CHECK("retval != 0x7f000001", *retval == 0x7f000001);
    free(retval);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(pigsty_entry_ctx_tests)
    pigsty_entry_ctx *pigsty = NULL, *p;
    pigsty = add_signature_to_pigsty_entry(pigsty, "oink");
    pigsty = add_signature_to_pigsty_entry(pigsty, "roc!");
    CUTE_CHECK("pigsty == NULL", pigsty != NULL);
    CUTE_CHECK("pigsty->signature_name != oink", strcmp(pigsty->signature_name, "oink") == 0);
    CUTE_CHECK("pigsty->next == NULL", pigsty->next != NULL);
    CUTE_CHECK("pigsty->next->signature_name != roc!", strcmp(pigsty->next->signature_name, "roc!") == 0);
    CUTE_CHECK("pigsty->next->next != NULL", pigsty->next->next == NULL);
    p = get_pigsty_entry_signature_name("oink", pigsty);
    CUTE_CHECK("p == NULL", p != NULL);
    CUTE_CHECK("p->signature_name != oink", strcmp(p->signature_name, "oink") == 0);
    p = get_pigsty_entry_signature_name("not-added", pigsty);
    CUTE_CHECK("p != NULL", p == NULL);
    CUTE_CHECK("get_pigsty_entry_count() != 2", get_pigsty_entry_count(pigsty) == 2);
    p = get_pigsty_entry_by_index(1, pigsty);
    CUTE_CHECK("p == NULL", p != NULL);
    CUTE_CHECK("p->signature_name != roc!", strcmp(p->signature_name, "roc!") == 0);
    p = get_pigsty_entry_by_index(-1, pigsty);
    CUTE_CHECK("p != NULL", p == NULL);
    del_pigsty_entry(pigsty);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(pigsty_conf_set_ctx_tests)
    pigsty_entry_ctx *pigsty = NULL;
    pigsty_conf_set_ctx *cp = NULL;
    pigsty = add_signature_to_pigsty_entry(pigsty, "oink");
    CUTE_CHECK("pigsty == NULL", pigsty != NULL);
    pigsty->conf = add_conf_to_pigsty_conf_set(pigsty->conf, kIpv4_version, "abc", 3);
    pigsty->conf = add_conf_to_pigsty_conf_set(pigsty->conf, kIpv4_tos, "xyz.", 4);
    CUTE_CHECK("pigsty->conf == NULL", pigsty->conf != NULL);
    CUTE_CHECK("pigsty->conf->index != kIpv4_version", pigsty->conf->field->index == kIpv4_version);
    CUTE_CHECK("pigsty->conf->dsize != 3", pigsty->conf->field->dsize == 3);
    CUTE_CHECK("pigsty->conf->data != abc", strcmp(pigsty->conf->field->data,"abc") == 0);
    CUTE_CHECK("pigsty->conf->next == NULL", pigsty->conf->next != NULL);
    CUTE_CHECK("pigsty->conf->next->index != kIpv4_tos", pigsty->conf->next->field->index == kIpv4_tos);
    CUTE_CHECK("pigsty->conf->next->dsize != 4", pigsty->conf->next->field->dsize == 4);
    CUTE_CHECK("pigsty->conf->next->data != xyz.", strcmp(pigsty->conf->next->field->data,"xyz.") == 0);
    pigsty = add_signature_to_pigsty_entry(pigsty, "oink2");
    cp = get_pigsty_conf_set_by_index(1, pigsty->conf);
    CUTE_CHECK("cp == NULL", cp != NULL);
    CUTE_CHECK("cp != pigsty->conf->next", cp == pigsty->conf->next);
    CUTE_CHECK("get_pigsty_conf_set_count() != 2", get_pigsty_conf_set_count(pigsty->conf) == 2);
    cp = get_pigsty_conf_set_by_index(99, pigsty->conf);
    CUTE_CHECK("cp != NULL", cp == NULL);
    del_pigsty_entry(pigsty);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(ip_packet_making_tests)
    struct ip4 ip4_hdr, ip4_hdr_parsed;
    struct ip4 *ip4_hdr_parsed_p = NULL;
    unsigned char *packet = NULL;
    unsigned char *expected_packet = "\x45\x00\x00\x14\xde\xad\xbe\xef\x10\x06\xab\xcd\x7f\x00\x00\x01\x7f\x00\x00\x02";
    size_t p = 0;
    size_t packet_size    = 0;
    ip4_hdr.version       = 0x4;
    ip4_hdr.ihl           = 0x5;
    ip4_hdr.tos           = 0;
    ip4_hdr.tlen          = 0x0014;
    ip4_hdr.id            = 0xdead;
    ip4_hdr.flags_fragoff = 0xbeef;
    ip4_hdr.ttl           = 0x10;
    ip4_hdr.protocol      = 0x6;
    ip4_hdr.chsum         = 0xabcd;
    ip4_hdr.src           = 0x7f000001;
    ip4_hdr.dst           = 0x7f000002;
    ip4_hdr.payload       = NULL;
    ip4_hdr.payload_size  = 0;
    packet = mk_ip4_buffer(&ip4_hdr, &packet_size);
    CUTE_CHECK_EQ("packet_size != ip4_hdr.tlen", ip4_hdr.tlen, packet_size);
    CUTE_CHECK("packet == NULL", packet != NULL);
    for (p = 0; p < packet_size; p++) {
        CUTE_CHECK_EQ("packet[i] != expected_packet[i]", packet[p], expected_packet[p]);
    }
    ip4_hdr_parsed_p = &ip4_hdr_parsed;
    parse_ip4_dgram(&ip4_hdr_parsed_p, packet, ip4_hdr.tlen);
    CUTE_CHECK_EQ("ip4_hdr_parsed.version != 0x4", ip4_hdr_parsed.version, 0x4);
    CUTE_CHECK_EQ("ip4_hdr_parsed.ihl != 0x5", ip4_hdr_parsed.ihl, 0x5);
    CUTE_CHECK_EQ("ip4_hdr_parsed.tos != 0x0", ip4_hdr_parsed.tos, 0x0);
    CUTE_CHECK_EQ("ip4_hdr_parsed.tlen != 0x0014", ip4_hdr_parsed.tlen, 0x14);
    CUTE_CHECK_EQ("ip4_hdr_parsed.id != 0xdead", ip4_hdr_parsed.id, 0xdead);
    CUTE_CHECK_EQ("ip4_hdr_parsed.flags_fragoff != 0xbeef", ip4_hdr_parsed.flags_fragoff, 0xbeef);
    CUTE_CHECK_EQ("ip4_hdr_parsed.ttl != 0x10", ip4_hdr_parsed.ttl, 0x10);
    CUTE_CHECK_EQ("ip4_hdr_parsed.protocol != 0x6", ip4_hdr_parsed.protocol, 0x6);
    CUTE_CHECK_EQ("ip4_hdr_parsed.chsum != 0xabcd", ip4_hdr_parsed.chsum, 0xabcd);
    CUTE_CHECK_EQ("ip4_hdr_parsed.src != 0x7f000001", ip4_hdr_parsed.src, 0x7f000001);
    CUTE_CHECK_EQ("ip4_hdr_parsed.dst != 0x7f000002", ip4_hdr_parsed.dst, 0x7f000002);
    CUTE_CHECK_EQ("ip4_hdr_parsed.payload != NULL", ip4_hdr_parsed.payload, NULL);
    CUTE_CHECK_EQ("ip4_hdr_parsed.payload_size != 0", ip4_hdr_parsed.payload_size, 0);
    free(packet);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(udp_packet_making_tests)
    unsigned char *packet = NULL;
    unsigned char *expected_packet = "\xaa\xbb\xcc\xdd\x00\x08\xee\xff";
    size_t packet_size = 0, p = 0;
    struct udp udp_hdr, udp_hdr_parsed, *udp_hdr_p = NULL;
    udp_hdr.src          = 0xaabb;
    udp_hdr.dst          = 0xccdd;
    udp_hdr.len          = 0x8;
    udp_hdr.chsum        = 0xeeff;
    udp_hdr.payload      = NULL;
    udp_hdr.payload_size = 0;
    packet = mk_udp_buffer(&udp_hdr, &packet_size);
    CUTE_CHECK_NEQ("packet == NULL", packet, NULL);
    CUTE_CHECK_EQ("packet_size != 8", packet_size, 8);
    for (p = 0; p < packet_size; p++) {
	CUTE_CHECK_EQ("packet[p] != expected_packet[p]", packet[p], expected_packet[p]);
    }
    udp_hdr_p = &udp_hdr_parsed;
    parse_udp_dgram(&udp_hdr_p, packet, packet_size);
    CUTE_CHECK_EQ("udp_hdr_parsed.src != 0xaabb", udp_hdr_parsed.src, 0xaabb);
    CUTE_CHECK_EQ("udp_hdr_parsed.dst != 0xccdd", udp_hdr_parsed.dst, 0xccdd);
    CUTE_CHECK_EQ("udp_hdr_parsed.len != 0x8", udp_hdr_parsed.len, 0x8);
    CUTE_CHECK_EQ("udp_hdr_parsed.chsum != 0xeeff", udp_hdr_parsed.chsum, 0xeeff);
    CUTE_CHECK_EQ("udp_hdr_parsed.payload != NULL", udp_hdr_parsed.payload, NULL);
    CUTE_CHECK_EQ("udp_hdr_parsed.payload_size != 0", udp_hdr_parsed.payload_size, 0);
    free(packet);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(tcp_packet_making_tests)
    unsigned char *packet = NULL;
    unsigned char *expected_packet = "\xde\xad\xbe\xef\x00\x11\x22\x33\x33\x22\x11\x00\x50\x03\x11\x44\x77\x88\xaa\xff";
    size_t packet_size = 0, p = 0;
    struct tcp tcp_hdr, tcp_hdr_parsed, *tcp_hdr_p = NULL;
    tcp_hdr.src = 0xdead;
    tcp_hdr.dst = 0xbeef;
    tcp_hdr.seqno = 0x00112233;
    tcp_hdr.ackno = 0x33221100;
    tcp_hdr.len = 0x5;
    tcp_hdr.reserv = 0x0;
    tcp_hdr.flags = 0x03;
    tcp_hdr.window = 0x1144;
    tcp_hdr.chsum = 0x7788;
    tcp_hdr.urgp = 0xaaff;
    tcp_hdr.payload = NULL;
    tcp_hdr.payload_size = 0;
    packet = mk_tcp_buffer(&tcp_hdr, &packet_size);
    CUTE_CHECK_NEQ("packet == NULL", packet, NULL);
    CUTE_CHECK_EQ("packet_size != 20", packet_size, 20);
    for (p = 0; p < packet_size; p++) {
        CUTE_CHECK_EQ("packet[i] != expected_packet[i]", packet[p], expected_packet[p]);
    }
    tcp_hdr_p = &tcp_hdr_parsed;
    parse_tcp_dgram(&tcp_hdr_p, packet, packet_size);
    CUTE_CHECK_EQ("tcp_hdr.src != 0xdead", tcp_hdr_parsed.src, 0xdead);
    CUTE_CHECK_EQ("tcp_hdr.dst != 0xbeef", tcp_hdr_parsed.dst, 0xbeef);
    CUTE_CHECK_EQ("tcp_hdr.seqno != 0x00112233", tcp_hdr_parsed.seqno, 0x00112233);
    CUTE_CHECK_EQ("tcp_hdr.ackno != 0x33221100", tcp_hdr_parsed.ackno, 0x33221100);
    CUTE_CHECK_EQ("tcp_hdr.len != 0x5", tcp_hdr_parsed.len, 0x5);
    CUTE_CHECK_EQ("tcp_hdr.reserv != 0x0", tcp_hdr_parsed.reserv, 0x0);
    CUTE_CHECK_EQ("tcp_hdr.flags != 0x03", tcp_hdr_parsed.flags, 0x03);
    CUTE_CHECK_EQ("tcp_hdr.chsum != 0x7788", tcp_hdr_parsed.chsum, 0x7788);
    CUTE_CHECK_EQ("tcp_hdr.urgp != 0xaaff", tcp_hdr_parsed.urgp, 0xaaff);
    CUTE_CHECK_EQ("tcp_hdr.payload != NULL", tcp_hdr_parsed.payload, NULL);
    CUTE_CHECK_EQ("tcp_hdr.payload_size != 0", tcp_hdr_parsed.payload_size, 0);
    free(packet);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(ip4_chsum_evaluation_tests)
    struct ip4 ip;
    unsigned short expected_chsum = 0xb1e6;
    ip.version = 0x4;
    ip.ihl = 0x5;
    ip.tos = 0x00;
    ip.tlen = 0x003c;
    ip.id = 0x1c46;
    ip.flags_fragoff = 0x4000;
    ip.ttl = 0x40;
    ip.protocol = 0x06;
    ip.chsum = 0x0;
    ip.src = 0xac100a63;
    ip.dst = 0xac100a0c;
    ip.payload = NULL;
    ip.payload_size = 0;
    ip.chsum = eval_ip4_chsum(ip);
    CUTE_CHECK_EQ("ip.chsum != expected_chsum", ip.chsum, expected_chsum);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(udp_chsum_evaluation_tests)
    struct udp uhdr;
    unsigned short expected_chsum = 0xd199;
    uhdr.src = 0x35;
    uhdr.dst = 0xec34;
    uhdr.len = 0x9a;
    uhdr.chsum = 0x0;
    uhdr.payload = "\x27\x47\x81\x80\x00\x01\x00\x03\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67"
                   "\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x02\x62\x72\x00\x00\x01\x00\x01\x03"
                   "\x77\x77\x77\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x02\x62\x72\x00"
                   "\x00\x01\x00\x01\x00\x00\x01\x2b\x00\x04\xad\xc2\x76\x37\x03\x77\x77\x77"
                   "\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x02\x62\x72\x00\x00\x01\x00"
                   "\x01\x00\x00\x01\x2b\x00\x04\xad\xc2\x76\x38\x03\x77\x77\x77\x06\x67\x6f"
                   "\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x02\x62\x72\x00\x00\x01\x00\x01\x00\x00"
                   "\x01\x2b\x00\x04\xad\xc2\x76\x3f\x00\x00\x00\x13\x00\x21\x00\x34\x00\x42"
                   "\x00\x55";
    uhdr.payload_size = 146;
    uhdr.chsum = eval_udp_chsum(uhdr, 0xc01e460f, 0xc01e460a, uhdr.len);
    CUTE_CHECK_EQ("uhdr.chsum != expected_chsum", uhdr.chsum, expected_chsum);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(tcp_chsum_evaluation_tests)
    struct tcp uhdr;
    unsigned short expected_chsum = 0xbc6e;
    uhdr.src = 0x0050;
    uhdr.dst = 0xc1ed;
    uhdr.seqno = 0xcb6dd9e0;
    uhdr.ackno = 0x6fc3ae65;
    uhdr.len = 0x5;
    uhdr.reserv = 0;
    uhdr.flags= 0x10;
    uhdr.window = 0x003a;
    uhdr.chsum = 0x0;
    uhdr.urgp = 0x0;
    uhdr.payload_size = 0;
    uhdr.payload = NULL;
    uhdr.chsum = eval_tcp_ip4_chsum(uhdr, 0xcdb9d80a, 0xc0a8070a);
    CUTE_CHECK_EQ("uhdr.chsum != expected_chsum", uhdr.chsum, expected_chsum);
    uhdr.src = 0x0050;
    uhdr.dst = 0xc1f6;
    uhdr.seqno = 0x040343c2;
    uhdr.ackno = 0xf2690cd1;
    uhdr.len = 0x5;
    uhdr.reserv = 0;
    uhdr.flags = 0x18;
    uhdr.window = 0x00fb;
    uhdr.chsum = 0x0;
    uhdr.urgp = 0x0;
    uhdr.payload_size = 223;
    uhdr.payload = "\x48\x54\x54\x50\x2f\x31\x2e\x31\x20\x32\x30\x30\x20\x4f\x4b\x0d\x0a\x54\x72\x61"
		   "\x6e\x73\x66\x65\x72\x2d\x45\x6e\x63\x6f\x64\x69\x6e\x67\x3a\x20\x63\x68\x75\x6e"
		   "\x6b\x65\x64\x0d\x0a\x44\x61\x74\x65\x3a\x20\x46\x72\x69\x2c\x20\x32\x30\x20\x4a"
		   "\x75\x6e\x20\x32\x30\x31\x34\x20\x31\x36\x3a\x31\x38\x3a\x31\x38\x20\x47\x4d\x54"
		   "\x0d\x0a\x53\x65\x72\x76\x65\x72\x3a\x20\x57\x61\x72\x70\x2f\x32\x2e\x31\x2e\x33"
		   "\x2e\x33\x0d\x0a\x41\x63\x63\x65\x73\x73\x2d\x43\x6f\x6e\x74\x72\x6f\x6c\x2d\x41"
		   "\x6c\x6c\x6f\x77\x2d\x4f\x72\x69\x67\x69\x6e\x3a\x20\x68\x74\x74\x70\x3a\x2f\x2f"
		   "\x78\x6b\x63\x64\x2e\x63\x6f\x6d\x0d\x0a\x41\x63\x63\x65\x73\x73\x2d\x43\x6f\x6e"
		   "\x74\x72\x6f\x6c\x2d\x41\x6c\x6c\x6f\x77\x2d\x43\x72\x65\x64\x65\x6e\x74\x69\x61"
		   "\x6c\x73\x3a\x20\x74\x72\x75\x65\x0d\x0a\x43\x6f\x6e\x74\x65\x6e\x74\x2d\x54\x79"
		   "\x70\x65\x3a\x20\x74\x65\x78\x74\x2f\x70\x6c\x61\x69\x6e\x0d\x0a\x0d\x0a\x30\x0d"
		   "\x0a\x0d\x0a";
    expected_chsum = 0x4e24;
    uhdr.chsum = eval_tcp_ip4_chsum(uhdr, 0x6b066222, 0xc0a8070a);
    CUTE_CHECK_EQ("uhdr.chsum != expected_chsum", uhdr.chsum, expected_chsum);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(netmask_get_range_type_tests)
    pig_addr_range_type_t type = kNone;
    type = get_range_type("*");
    CUTE_CHECK("type != kWild", type == kWild);
    type = get_range_type("255.*.*.*");
    CUTE_CHECK("type != kWild", type == kWild);
    type = get_range_type("255.255.*.*");
    CUTE_CHECK("type != kWild", type == kWild);
    type = get_range_type("255.255.255.*");
    CUTE_CHECK("type != kWild", type == kWild);
    type = get_range_type("255.255.255.255.*");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("255...*");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("127.0.0.1");
    CUTE_CHECK("type != kAddr", type == kAddr);
    type = get_range_type("1272.0.0.1");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("127.1230.0.1");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("127.0.12310.1");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("127.0.0.112312");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("192.30.70.3/20");
    CUTE_CHECK("type != kCidr", type == kCidr);
    type = get_range_type("127.0.0.1.2");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("220.78.168.0/21");
    CUTE_CHECK("type != kCidr", type == kCidr);
    type = get_range_type("299.78.168.0/21");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("220.78.168.0.27/21");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("192.30.70.1113/20");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("192.30.1270.3/20");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("192.a30.70.3/20");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("192.2330.70.3/20");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("north-american-ip");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("european-ip");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("asian-ip");
    CUTE_CHECK("type != kNone", type == kNone);
    type = get_range_type("south-american-ip");
    CUTE_CHECK("type != kNone", type == kNone);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(run_tests)
    printf("running unit tests...\n\n");
    CUTE_RUN_TEST(pigsty_file_parsing_tests);
    CUTE_RUN_TEST(to_int_tests);
    CUTE_RUN_TEST(to_str_tests);
    CUTE_RUN_TEST(to_ipv4_tests);
    CUTE_RUN_TEST(pigsty_entry_ctx_tests);
    CUTE_RUN_TEST(pigsty_conf_set_ctx_tests);
    CUTE_RUN_TEST(ip_packet_making_tests);
    CUTE_RUN_TEST(udp_packet_making_tests);
    CUTE_RUN_TEST(tcp_packet_making_tests);
    CUTE_RUN_TEST(ip4_chsum_evaluation_tests);
    CUTE_RUN_TEST(udp_chsum_evaluation_tests);
    CUTE_RUN_TEST(tcp_chsum_evaluation_tests);
    CUTE_RUN_TEST(netmask_get_range_type_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(run_tests)
