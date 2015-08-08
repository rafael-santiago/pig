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
#include "../icmp.h"
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

    test_pigsty = "[ signature = \"valid signature\", ip.version = 4, ip.tos = 5, ip.src = 127.0.0.1, ip.dst = 127.0.0.1, ip.protocol = 1 ]"; //  valid pigsty entry.
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
    CUTE_CHECK("pigsty->conf->next->next->next->field == NULL", pigsty->conf->next->next->next->field != NULL);
    CUTE_CHECK("pigsty->conf->next->next->next->field->index != kIpv4_dst", pigsty->conf->next->next->next->field->index == kIpv4_dst);
    CUTE_CHECK("pigsty->conf->next->next->next->next->field == NULL", pigsty->conf->next->next->next->next->field != NULL);
    CUTE_CHECK("pigsty->conf->next->next->next->next->field->index != kIpv4_protocol", pigsty->conf->next->next->next->next->field->index == kIpv4_protocol);
    CUTE_CHECK("pigsty->conf->next->next->next->next->next != NULL", pigsty->conf->next->next->next->next->next == NULL);
    remove("test.pigsty");
    del_pigsty_entry(pigsty);
    pigsty = NULL;
    test_pigsty = "[ip.version = 4, ip.protocol = 1, icmp.code = 4, icmp.type = 3, ip.src = 10.2.2.2, ip.dst = 172.21.0.50 ]";
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    CUTE_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");

    test_pigsty = "[ ip.version = 4, ip.src = 10.2.2.2, ip.dst = 172.21.0.50, ip.id = 0x3ba3,"
                  "ip.ttl = 63, ip.protocol = 1, icmp.type = 3, icmp.code = 4, "
                  "icmp.payload = \"\\x05\\x9e\\x45\\x00\\x05\\xf2\\x0a\\xf1\\x40\\x00\\x7f\\x06\\xb6\\x23"
                  "\\xac\\x15\\x00\\x32\\xc0\\xa8\\xc8\\x01\\xd9\\xc8\\x00\\x58\\x7f\\x07\\xa3\\x1b\\xb6\\xd4"
                  "\\xd0\\xa0\\x50\\x18\\x01\\x00\\x3a\\xd6\\x00\\x00\\x00\\x00\\x05\\xc6\\x6c\\x82\\x05\\xc2"
                  "\\x30\\x82\\x05\\xbe\\xa1\\x03\\x02\\x01\\x05\\xa2\\x03\\x02\\x01\\x0c\\xa3\\x82\\x05\\x36"
                  "\\x30\\x82\\x05\\x32\\x30\\x82\\x05\\x2e\\xa1\\x03\\x02\\x01\\x01\\xa2\\x82\\x05\\x25\\x04"
                  "\\x82\\x05\\x21\\x6e\\x82\\x05\\x1d\\x30\\x82\\x05\\x19\\xa0\\x03\\x02\\x01\\x05\\xa1\\x03"
                  "\\x02\\x01\\x0e\\xa2\\x07\\x03\\x05\\x00\\x00\\x00\\x00\\x00\\xa3\\x82\\x04\\x5e\\x61\\x82"
                  "\\x04\\x5a\\x30\\x82\\x04\\x56\\xa0\\x03\\x02\\x01\\x05\\xa1\\x0f\\x1b\\x0d\\x4d\\x49\\x44"
                  "\\x47\\x41\\x52\\x44\\x2e\\x4c\\x4f\\x43\\x41\\x4c\\xa2\\x22\\x30\\x20\\xa0\\x03\\x02\\x01"
                  "\\x02\\xa1\\x19\\x30\\x17\\x1b\\x06\\x6b\\x72\\x62\\x74\\x67\\x74\\x1b\\x0d\\x4d\\x49\\x44"
                  "\\x47\\x41\\x52\\x44\\x2e\\x4c\\x4f\\x43\\x41\\x4c\\xa3\\x82\\x04\\x18\\x30\\x82\\x04\\x14"
                  "\\xa0\\x03\\x02\\x01\\x12\\xa1\\x03\\x02\\x01\\x02\\xa2\\x82\\x04\\x06\\x04\\x82\\x04\\x02"
                  "\\x1d\\xf8\\x07\\x63\\x65\\x6f\\x3f\\xab\\x1b\\x20\\x5f\\x28\\x1d\\x29\\xad\\x69\\x5c\\x74"
                  "\\x57\\x0f\\x66\\x7c\\x13\\xa3\\x3b\\xef\\x67\\xcf\\xb7\\xbe\\x62\\xc4\\xec\\x4b\\x71\\xaf"
                  "\\xd4\\xc6\\x57\\x74\\xf4\\xfe\\xca\\x69\\x05\\xb1\\x3f\\xac\\xf7\\xf3\\x28\\xc3\\x90\\x6c"
                  "\\x8e\\x38\\xbc\\x90\\x9b\\x86\\xd0\\x2e\\xb5\\x56\\x48\\x80\\xfd\\x09\\x2c\\x41\\x5b\\x63"
                  "\\xce\\xb2\\x72\\xdf\\x68\\x35\\xae\\x88\\xda\\x26\\x2f\\x91\\xd2\\x0d\\x28\\x0c\\x1b\\x5c"
                  "\\x28\\x6a\\x24\\x17\\xaf\\x29\\x4b\\x66\\x33\\x24\\xfa\\x76\\x54\\xe2\\x0d\\xd6\\x5e\\xfd"
                  "\\x38\\xe9\\x72\\x83\\x69\\x5e\\x1e\\x33\\x2c\\xca\\x9b\\x42\\xf7\\x18\\xe4\\xe6\\x4d\\xb5"
                  "\\x92\\xd7\\xc6\\x96\\x53\\xa9\\x4a\\x09\\xd5\\xb1\\x3d\\x1d\\x66\\xd6\\xbd\\xd9\\xaa\\xf0"
                  "\\x52\\xab\\x96\\x17\\xae\\x83\\xd7\\x36\\x77\\x73\\x82\\xaf\\xbf\\xb5\\x4e\\x7a\\x3c\\x4b"
                  "\\xbb\\xfc\\x0d\\x9c\\x5e\\xe0\\x3a\\x29\\x16\\x5c\\x87\\x7b\\xfc\\x35\\x27\\x9f\\xaa\\xba"
                  "\\xeb\\x3e\\x0c\\x20\\xab\\xbe\\x07\\x66\\xcc\\x4c\\xcf\\x9d\\x29\\x94\\x2b\\x8b\\x28\\x67"
                  "\\x6b\\xf2\\xbe\\x18\\x5e\\xcf\\xa0\\xdf\\x55\\x83\\xd6\\x29\\x61\\x9a\\x64\\xda\\x60\\x18"
                  "\\x03\\xe4\\x11\\x5a\\xfd\\x6c\\x0b\\xb3\\x59\\xc9\\x49\\xd3\\xd0\\x86\\x33\\x73\\xfc\\x36"
                  "\\x46\\xd3\\xab\\x57\\x6e\\xa2\\x0b\\x27\\x2f\\x05\\xd6\\x9b\\x1a\\xc1\\x42\\x9a\\x21\\x86"
                  "\\x06\\x74\\x01\\xb4\\x8d\\xe4\\xb4\\x46\\xc2\\x8f\\xfe\\x56\\x62\\xa9\\x6b\\xf5\\x94\\x93"
                  "\\x6b\\x79\\x87\\x38\\xf9\\x51\\x96\\x3e\\x64\\x49\\x6a\\x1e\\x97\\x83\\x90\\x14\\xa7\\x3d"
                  "\\x1e\\xe9\\x69\\x6a\\xa6\\x75\\x85\\x51\\x4b\\x39\\xbb\\x87\\x73\\x17\\x7c\\x53\\xa7\\x65"
                  "\\xd7\\xbe\\x4d\\x4b\\x98\\x34\\xd3\\x84\\xc1\\x25\\x21\\x41\\x5c\\x49\\x11\\x92\\xfb\\x01"
                  "\\xfc\\x32\\x2b\\x51\\x80\\x29\\x62\\x2f\\x0e\\xf1\\xcd\\x2d\\x09\\x4e\\x6O\","
                  "signature = \"icmp echo\" ]";
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    CUTE_CHECK("pigsty == NULL", pigsty != NULL);
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
    size_t sz = 1;
    CUTE_CHECK("to_str() != NULL", to_str(NULL, NULL) == NULL);
    CUTE_CHECK("to_str() != NULL", to_str(NULL, &sz) == NULL);
    CUTE_CHECK("sz != 0", sz == 0);
    retval = to_str("\"\\n\\r\\t\"", &sz);
    CUTE_CHECK("to_str() != \"\\n\\r\\t\"", strcmp(retval, "\n\r\t") == 0);
    CUTE_CHECK("sz != 3", sz == 3);
    free(retval);
    retval = to_str("\"r\\nr\\nn\\ne\\n\"", &sz);
    CUTE_CHECK("sz != 8", sz == 8);
    CUTE_CHECK("to_str() != \"r\\nr\\nn\\ne\\n\"", strcmp(retval, "r\nr\nn\ne\n") == 0);
    free(retval);
    retval = to_str("\"\x61\x62\x63\"", &sz);
    CUTE_CHECK("sz != 3", sz == 3);
    CUTE_CHECK("to_str() != \"abc\"", strcmp(retval, "abc") == 0);
    free(retval);
    retval = to_str("\"\x61\x62\x6362\"", &sz);
    CUTE_CHECK("sz != 3", sz == 3);
    CUTE_CHECK("to_str() != \"abb\"", strcmp(retval, "abb") == 0);
    free(retval);
    retval = to_str("\"\x9tab!\"", &sz);
    CUTE_CHECK("sz != 5", sz == 5);
    CUTE_CHECK("to_str() != \"\\ttab!\"", strcmp(retval, "\ttab!") == 0);
    free(retval);
    retval = to_str("\"well behaved string.\"", &sz);
    CUTE_CHECK("sz != 20", sz == 20);
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
    char *data = "abc";
    pigsty->conf = add_conf_to_pigsty_conf_set(pigsty->conf, kIpv4_version, data, strlen(data));
    pigsty->conf = add_conf_to_pigsty_conf_set(pigsty->conf, kIpv4_tos, "xyz.", 4);
    CUTE_CHECK("pigsty->conf == NULL", pigsty->conf != NULL);
    CUTE_CHECK("pigsty->conf->index != kIpv4_version", pigsty->conf->field->index == kIpv4_version);
    CUTE_CHECK("pigsty->conf->dsize != strlen(data)", pigsty->conf->field->dsize == strlen(data));
    CUTE_CHECK("pigsty->conf->data != data", strcmp(pigsty->conf->field->data, data) == 0);
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

CUTE_TEST_CASE(icmp_packet_making_tests)
    struct icmp icmp_hdr, *icmp_hdr_p = NULL;
    unsigned char *expected_packet = "\x00\x00\x54\xde\x00\x01\x00\x7d\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69";
    unsigned char *packet = NULL;
    size_t packet_size = 0, p = 0;
    icmp_hdr.type = 0;
    icmp_hdr.code = 0;
    icmp_hdr.chsum = 0x54de;
    icmp_hdr.payload = "\x00\x01\x00\x7d\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69";
    icmp_hdr.payload_size = 36;
    packet = mk_icmp_buffer(&icmp_hdr, &packet_size);
    CUTE_CHECK_EQ("packet_size != 40", packet_size, 40);
    for (p = 0; p < packet_size; p++) {
        CUTE_CHECK_EQ("packet[i] != expected_packet[i]", packet[p], expected_packet[p]);
    }
    icmp_hdr_p = &icmp_hdr;
    memset(&icmp_hdr, 0, sizeof(struct icmp));
    parse_icmp_dgram(&icmp_hdr_p, packet, packet_size);
    CUTE_CHECK_EQ("icmp_hdr.type != 0", icmp_hdr.type, 0);
    CUTE_CHECK_EQ("icmp_hdr.code != 0", icmp_hdr.code, 0);
    CUTE_CHECK_NEQ("icmp.payload == NULL", icmp_hdr.payload, NULL);
    CUTE_CHECK_EQ("icmp.payload_size != 36", icmp_hdr.payload_size, 36);
    for (p = 4; p < packet_size; p++) {
        CUTE_CHECK_EQ("icmp.payload[i] != expected_packet[i]", icmp_hdr.payload[p - 4], expected_packet[p]);
    }
    free(packet);
    free(icmp_hdr.payload);
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

CUTE_TEST_CASE(icmp_chsum_evaluation_tests)
    struct icmp icmp_hdr;
    unsigned short expected_chsum = 0x54de;
    icmp_hdr.type = 0;
    icmp_hdr.code = 0;
    icmp_hdr.chsum = 0x00;
    icmp_hdr.payload = "\x00\x01\x00\x7d\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x61\x62\x63\x64\x65\x66\x67\x68\x69";
    icmp_hdr.payload_size = 36;
    CUTE_CHECK("eval_icmp_chsum() != expected_chsum", eval_icmp_chsum(icmp_hdr) == expected_chsum);
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

CUTE_TEST_CASE(to_ipv4_mask_tests)
    unsigned int *mask = NULL;
    mask = to_ipv4_mask("*");
    CUTE_CHECK("mask == NULL", mask != NULL);
    CUTE_CHECK("mask != 0xffffffff", *mask == 0xffffffff);
    free(mask);
    mask = to_ipv4_mask("127.*.*.*");
    CUTE_CHECK("mask == NULL", mask != NULL);
    CUTE_CHECK("mask != 0x7fffffff", *mask == 0x7fffffff);
    free(mask);
    mask = to_ipv4_mask("127.0.*.*");
    CUTE_CHECK("mask == NULL", mask != NULL);
    CUTE_CHECK("mask != 0x7f00ffff", *mask == 0x7f00ffff);
    free(mask);
    mask = to_ipv4_mask("127.0.0.*");
    CUTE_CHECK("mask == NULL", mask != NULL);
    CUTE_CHECK("mask != 0x7f0000ff", *mask == 0x7f0000ff);
    free(mask);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(to_ipv4_cidr_tests)
    unsigned int *mask = NULL;
    unsigned int cidr_range = 0;
    mask = to_ipv4_cidr("220.78.168.0/21", &cidr_range);
    CUTE_CHECK("mask == NULL", mask != NULL);
    CUTE_CHECK("mask != 0xdc4eafff", *mask == 0xdc4eafff);
    CUTE_CHECK("mask->cidr_range != 21", cidr_range == 21);
    free(mask);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(pig_target_addr_ctx_tests)
    pig_target_addr_ctx *addr = NULL;
    addr = add_target_addr_to_pig_target_addr(addr, "127.0.0.1");
    addr = add_target_addr_to_pig_target_addr(addr, "127.*.*.*");
    addr = add_target_addr_to_pig_target_addr(addr, "220.78.168.0/21");
    CUTE_CHECK("addr == NULL", addr != NULL);
    CUTE_CHECK("addr->v != 4", addr->v == 4);
    CUTE_CHECK("addr->asize != 4", addr->asize == 4);
    CUTE_CHECK("addr->type != kAddr", addr->type == kAddr);
    CUTE_CHECK("addr->addr == NULL", addr->addr != NULL);
    CUTE_CHECK("*addr->addr != 0x7f000001", *(unsigned int *)addr->addr == 0x7f000001);

    CUTE_CHECK("addr->next == NULL", addr->next != NULL);
    CUTE_CHECK("addr->next->v != 4", addr->next->v == 4);
    CUTE_CHECK("addr->next->asize != 4", addr->next->asize == 4);
    CUTE_CHECK("addr->next->type != kWild", addr->next->type == kWild);
    CUTE_CHECK("addr->next->addr == NULL", addr->next->addr != NULL);
    CUTE_CHECK("*addr->next->addr != 0x7fffffff", *(unsigned int *)addr->next->addr == 0x7fffffff);

    CUTE_CHECK("addr->next->next == NULL", addr->next->next != NULL);
    CUTE_CHECK("addr->next->next->v != 4", addr->next->next->v == 4);
    CUTE_CHECK("addr->next->next->asize != 4", addr->next->next->asize == 4);
    CUTE_CHECK("addr->next->next->type != kCidr", addr->next->next->type == kCidr);
    CUTE_CHECK("addr->next->next->addr == NULL", addr->next->next->addr != NULL);
    CUTE_CHECK("*addr->next->next->addr != 0xdc4eafff", *(unsigned int *)addr->next->next->addr == 0xdc4eafff);
    del_pig_target_addr(addr);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(pig_hwaddr_ctx_tests)
    pig_hwaddr_ctx *hwaddr = NULL;
    unsigned char *p = NULL;
    unsigned int nt_addr[4] = { 0x7f000001, 0x000000, 0x000000, 0x000000 };
    hwaddr = add_hwaddr_to_pig_hwaddr(hwaddr, "\xde\xad\xbe\xef\x12\x34", nt_addr, 4);
    CUTE_CHECK("hwaddr == NULL", hwaddr != NULL);
    p = get_ph_addr_from_pig_hwaddr(nt_addr, hwaddr);
    CUTE_CHECK("p == NULL", p != NULL);
    nt_addr[0] = nt_addr[0] << 8;
    p = get_ph_addr_from_pig_hwaddr(nt_addr, hwaddr);
    del_pig_hwaddr(hwaddr);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(run_tests)
    printf("running unit tests...\n\n");
    CUTE_RUN_TEST(pigsty_file_parsing_tests);
    CUTE_RUN_TEST(to_int_tests);
    CUTE_RUN_TEST(to_str_tests);
    CUTE_RUN_TEST(to_ipv4_tests);
    CUTE_RUN_TEST(to_ipv4_mask_tests);
    CUTE_RUN_TEST(to_ipv4_cidr_tests);
    CUTE_RUN_TEST(pigsty_entry_ctx_tests);
    CUTE_RUN_TEST(pigsty_conf_set_ctx_tests);
    CUTE_RUN_TEST(pig_target_addr_ctx_tests);
    CUTE_RUN_TEST(pig_hwaddr_ctx_tests);
    CUTE_RUN_TEST(ip_packet_making_tests);
    CUTE_RUN_TEST(udp_packet_making_tests);
    CUTE_RUN_TEST(tcp_packet_making_tests);
    CUTE_RUN_TEST(icmp_packet_making_tests);
    CUTE_RUN_TEST(ip4_chsum_evaluation_tests);
    CUTE_RUN_TEST(udp_chsum_evaluation_tests);
    CUTE_RUN_TEST(tcp_chsum_evaluation_tests);
    CUTE_RUN_TEST(icmp_chsum_evaluation_tests);
    CUTE_RUN_TEST(netmask_get_range_type_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(run_tests)
