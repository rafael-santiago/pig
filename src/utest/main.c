/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "utest.h"
#include "../pigsty.h"
#include "../to_int.h"
#include "../to_str.h"
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

char *run_tests() {
    printf("running unit tests...\n\n");
    UTEST_RUN(pigsty_file_parsing_tests);
    UTEST_RUN(to_int_tests);
    UTEST_RUN(to_str_tests);
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
