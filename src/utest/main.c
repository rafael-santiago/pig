/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "utest.h"
#include "../types.h"
#include "../pigsty.h"
#include "../to_int.h"
#include "../to_str.h"
#include "../lists.h"
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

char *pigsty_file_parsing_tests() {
    pigsty_entry_ctx *pigsty = NULL;
    char *test_pigsty = "< ip.version = 4, ip.tos = 5, ip.src = 127.900.0.1 >";  //  invalid ip octect.
    printf("-- running pigsty_file_parsing_tests...\n");
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    UTEST_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");

    test_pigsty = "< ip.version = 4, ip.tos = 5, ip.src = 127.0.0.0.1 >";  //  invalid ip with more octects than expected.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    UTEST_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");

    test_pigsty = "< ip.version = 4x0, ip.tos = 5, ip.src = 127.0.0.1 >";  //  invalid ip version.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    UTEST_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");


    test_pigsty = "< ip.version = 0x00004, ip.tos = 5, ip.src = 127.0.0.1 > <ip.version = 4, ip.tlen = 20a >";  //  invalid ip version.
    write_to_file("test.pigsty", test_pigsty);
    pigsty = load_pigsty_data_from_file(pigsty, "test.pigsty");
    UTEST_CHECK("pigsty != NULL", pigsty == NULL);
    remove("test.pigsty");

    printf("-- passed.\n");
    return NULL;
}

char *to_int_tests() {
    printf("-- running to_int_tests...\n");
    UTEST_CHECK("to_int() != 4", to_int("4") == 4);
    UTEST_CHECK("to_int() != 0xf", to_int("0xf") == 0xf);
    UTEST_CHECK("to_int() != 0x0f", to_int("0x0f") == 0xf);
    UTEST_CHECK("to_int() != 0xe0", to_int("0xe0") == 0xe0);
    UTEST_CHECK("to_int() == 0", to_int(NULL) == 0);
    printf("-- passed.\n");
    return NULL;
}

char *to_str_tests() {
    char *retval = NULL;
    printf("-- running to_str_tests...\n");
    retval = to_str("\"\\n\\r\\t\"");
    UTEST_CHECK("to_str() != \"\\n\\r\\t\"", strcmp(retval, "\n\r\t") == 0);
    free(retval);
    retval = to_str("\"r\\nr\\nn\\ne\\n\"");
    UTEST_CHECK("to_str() != \"r\\nr\\nn\\ne\\n\"", strcmp(retval, "r\nr\nn\ne\n") == 0);
    free(retval);
    retval = to_str("\"\x61\x62\x63\"");
    UTEST_CHECK("to_str() != \"abc\"", strcmp(retval, "abc") == 0);
    free(retval);
    retval = to_str("\"\x61\x62\x6362\"");
    UTEST_CHECK("to_str() != \"abb\"", strcmp(retval, "abb") == 0);
    free(retval);
    retval = to_str("\"\x9tab!\"");
    UTEST_CHECK("to_str() != \"\\ttab!\"", strcmp(retval, "\ttab!") == 0);
    free(retval);
    retval = to_str("\"well behaved string.\"");
    UTEST_CHECK("to_str() != \"well behaved string.\"", strcmp(retval, "well behaved string.") == 0);
    free(retval);
    printf("-- passed.\n");
    return NULL;
}

char *pigsty_entry_ctx_tests() {
    pigsty_entry_ctx *pigsty = NULL;
    printf("-- running pigsty_entry_ctx_tests...\n");
    pigsty = add_signature_to_pigsty_entry(pigsty, "oink");
    pigsty = add_signature_to_pigsty_entry(pigsty, "roc!");
    UTEST_CHECK("pigsty == NULL", pigsty != NULL);
    UTEST_CHECK("pigsty->signature_name != oink", strcmp(pigsty->signature_name, "oink") == 0);
    UTEST_CHECK("pigsty->next == NULL", pigsty->next != NULL);
    UTEST_CHECK("pigsty->next->signature_name != roc!", strcmp(pigsty->next->signature_name, "roc!") == 0);
    UTEST_CHECK("pigsty->next->next != NULL", pigsty->next->next == NULL);
    del_pigsty_entry(pigsty);
    printf("-- passed.\n");
    return NULL;
}

char *pigsty_conf_set_ctx_tests() {
    pigsty_entry_ctx *pigsty = NULL;
    printf("-- running pigsty_conf_set_ctx_tests...\n");
    pigsty = add_signature_to_pigsty_entry(pigsty, "oink");
    UTEST_CHECK("pigsty == NULL", pigsty != NULL);
    pigsty->conf = add_conf_to_pigsty_conf_set(pigsty->conf, kIpv4_version, kNatureSet, "abc", 3);
    pigsty->conf = add_conf_to_pigsty_conf_set(pigsty->conf, kIpv4_tos, kNatureSet, "xyz.", 4);
    UTEST_CHECK("pigsty->conf == NULL", pigsty->conf != NULL);
    UTEST_CHECK("pigsty->conf->index != kIpv4_version", pigsty->conf->field.index == kIpv4_version);
    UTEST_CHECK("pigsty->conf->nature != kNatureSet", pigsty->conf->field.nature == kNatureSet);
    UTEST_CHECK("pigsty->conf->dsize != 3", pigsty->conf->field.dsize == 3);
    UTEST_CHECK("pigsty->conf->data != abc", strcmp(pigsty->conf->field.data,"abc") == 0);
    UTEST_CHECK("pigsty->conf->next == NULL", pigsty->conf->next != NULL);
    UTEST_CHECK("pigsty->conf->next->index != kIpv4_tos", pigsty->conf->next->field.index == kIpv4_tos);
    UTEST_CHECK("pigsty->conf->next->nature != kNatureSet", pigsty->conf->next->field.nature == kNatureSet);
    UTEST_CHECK("pigsty->conf->next->dsize != 4", pigsty->conf->next->field.dsize == 4);
    UTEST_CHECK("pigsty->conf->next->data != xyz.", strcmp(pigsty->conf->next->field.data,"xyz.") == 0);
    del_pigsty_entry(pigsty);
    printf("-- passed.\n");
}

char *run_tests() {
    printf("running unit tests...\n\n");
    UTEST_RUN(pigsty_file_parsing_tests);
    UTEST_RUN(to_int_tests);
    UTEST_RUN(to_str_tests);
    UTEST_RUN(pigsty_entry_ctx_tests);
    return NULL;
}

int main(int argc, char **argv) {
    char *complain = run_tests();
    if (complain != NULL) {
        printf("%s [%d test(s) ran]\n", complain, utest_ran_tests);
        return 1;
    }
    printf("*** all passed :)\n");
    return 0;
}
