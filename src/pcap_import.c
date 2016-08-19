#include "pcap_import.h"
#include "pcap2pigsty.h"
#include "options.h"
#include <stdio.h>

static int pcap_import_help() {
    printf("usage: pig --sub-task=pcap-import --pcap=<pcap-file-path> --pigsty=<pigsty-file-path> --include-ethernet-frames\n");
    return 0;
}

int pcap_import() {
    char *pcap = NULL;
    char *pigsty = NULL;
    char *incl_ethframe = NULL;
    char *signature_fmt = NULL;

    if (get_option("help", NULL) != NULL) {
        return pcap_import_help();
    }

    pcap = get_option("pcap", NULL);
    pigsty = get_option("pigsty", NULL);
    incl_ethframe = get_option("include-ethernet-frames", NULL);
    signature_fmt = get_option("signature-fmt", NULL);

    if (pcap == NULL) {
        printf("pig ERROR: --pcap option is missing.\n");
        return 1;
    }

    if (pigsty == NULL) {
        printf("pig ERROR: --pigsty option is missing.\n");
        return 1;
    }

    return pcap2pigsty(pigsty, pcap, signature_fmt, incl_ethframe != NULL);
}
