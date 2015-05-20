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
#include <cute.h>
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
    char *test_pigsty = "< ip.version = 4, ip.tos = 5, ip.src = 127.900.0.1 >";  //  invalid ip octect.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    CUTE_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");

    test_pigsty = "< ip.version = 4, ip.tos = 5, ip.src = 127.0.0.0.1 >";  //  invalid ip with more octects than expected.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    CUTE_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");

    test_pigsty = "< ip.version = 4x0, ip.tos = 5, ip.src = 127.0.0.1 >";  //  invalid ip version.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    CUTE_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");


    test_pigsty = "< ip.version = 0x00004, ip.tos = 5, ip.src = 127.0.0.1 > <ip.version = 4, ip.tlen = 20a >";  //  invalid ip version.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    CUTE_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");

    test_pigsty = "< signature = \"valid signature\", ip.version = 4, ip.tos = 5, ip.src = 127.0.0.1 >"; //  valid pigsty entry.
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
    CUTE_CHECK("retval != 0x7f000001", *retval != 0x7f000001);
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
    del_pigsty_entry(pigsty);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(pigsty_conf_set_ctx_tests)
    pigsty_entry_ctx *pigsty = NULL;
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

CUTE_TEST_CASE(run_tests)
    printf("running unit tests...\n\n");
    //CUTE_RUN_TEST(pigsty_file_parsing_tests);
    CUTE_RUN_TEST(to_int_tests);
    CUTE_RUN_TEST(to_str_tests);
    CUTE_RUN_TEST(to_ipv4_tests);
    CUTE_RUN_TEST(pigsty_entry_ctx_tests);
    CUTE_RUN_TEST(ip_packet_making_tests);
    CUTE_RUN_TEST(udp_packet_making_tests);
CUTE_TEST_CASE_END

CUTE_MAIN(run_tests)
