/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "pcap2pigsty.h"
#include "pcap.h"
#include "pktslicer.h"
#include "endianess.h"
#include "options.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

typedef int (*pcap_rec_dumper)(FILE *pigsty, const pcap_record_ctx *record);

typedef void (*dump_writer)(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size);

static pcap_rec_dumper g_pcap_rec_dumper_lt[0xff][0xff] = { 0 };

static pcap_rec_dumper g_pcap_rec_dumper_ip4tlayer_lt[0xff] = { 0 };

struct pkt_field_dumper_ctx {
    const char *field;
    dump_writer write;
};

//static pcap_rec_dumper g_pcap_rec_dumper_ip6tlayer_lt[0xffff] = { 0 };

static void init_pcap_rec_dumper_lookup_tables();

static int pigsty_data(FILE *pigsty, const pcap_record_ctx *record, const int incl_ethframe);

static void init_pcap_rec_dumper_lookup_table();

static int ethframe_dumper(FILE *pigsty, const pcap_record_ctx *record);

static int ip4_dumper(FILE *pigsty, const pcap_record_ctx *record);

static int arp_dumper(FILE *pigsty, const pcap_record_ctx *record);

static int generic_dumper(FILE *pigsty, const pcap_record_ctx *record);

static int icmp_dumper(FILE *pigsty, const pcap_record_ctx *record);

static int tcp_dumper(FILE *pigsty, const pcap_record_ctx *record);

static int udp_dumper(FILE *pigsty, const pcap_record_ctx *record);

static int dumper_textsec(struct pkt_field_dumper_ctx *dumper, size_t dumper_size, FILE *pigsty, const pcap_record_ctx *record);

static int generic_ip4tlayer_dumper(FILE *pigsty, const pcap_record_ctx *record);

static void dump_xdata(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size);

static void dump_ddata(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size);

static void dump_ip4addr(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size);

static void dump_xstring(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size);

static void dump_string(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size);

static void dump_tcpflags(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size);

static void dump_tcpflag(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size, const char *ntok);

static void dump_maddr(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size);

static void pigsty_ini(FILE *pigsty);

static void pigsty_finis(FILE *pigsty, const char *signature_fmt, const int index);

static void selwrite(dump_writer, FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size);

void get_option_label_from_field(char *option, const char *field);

#define NEW_PIGSTY "["

#define PIGSTY_NEW_ENTRY "\n "

#define PIGSTY_NEXT_ENTRY ","

#define NEXT_PIGSTY "\n]\n"

int pcap2pigsty(const char *pigsty_filepath, const char *pcap_filepath, const char *signature_fmt, const int incl_ethframe) {
    int exit_code = 1;
    pcap_file_ctx *pcap = NULL;
    pcap_record_ctx *rp = NULL;
    FILE *pigsty = NULL;
    int signature_index = 0;

    if (pigsty_filepath == NULL) {
        goto ___pcap2pigsty_cleanup;
    }

    if (pcap_filepath == NULL) {
        goto ___pcap2pigsty_cleanup;
    }

    if ((pcap = ld_pcap_file(pcap_filepath)) == NULL) {
        goto ___pcap2pigsty_cleanup;
    }

    if ((pigsty = fopen(pigsty_filepath, "a")) == NULL) {
        goto ___pcap2pigsty_cleanup;
    }

    init_pcap_rec_dumper_lookup_tables();

    exit_code = 0;

    for (rp = pcap->rec; rp != NULL && exit_code == 0; rp = rp->next) {
        pigsty_ini(pigsty);
        exit_code = pigsty_data(pigsty, rp, incl_ethframe);
        pigsty_finis(pigsty, signature_fmt, signature_index++);
    }

___pcap2pigsty_cleanup:

    if (pcap != NULL) {
        close_pcap_file(pcap);
    }

    if (pigsty != NULL) {
        fclose(pigsty);
    }

    if (exit_code != 0) {
        remove(pigsty_filepath);
    }

    return exit_code;
}

static void pigsty_ini(FILE *pigsty) {
    fprintf(pigsty, NEW_PIGSTY);
}

static void pigsty_finis(FILE *pigsty, const char *signature_fmt, const int index) {
    const char *fmt = "packet (%d)";
    int inval_fmt = 0;
    const char *sp = NULL;
    const char *sp_end = NULL;
    int o = 0;
    char str_fmt[255] = "";

    if (signature_fmt == NULL) {
        inval_fmt = 1;
    } else {
        for (sp = signature_fmt; *sp != 0 && inval_fmt == 0; sp++) {
            if (*sp == '%' && *(sp + 1) != 'd' || (*sp == '%' && *(sp + 1) == 'd' && o > 0)) {
                inval_fmt = 0;
            } else if (*sp == '%' && *(sp + 1) == 'd') {
                o++;
            }
        }
    }

    if (!inval_fmt) {
        fmt = signature_fmt;
    }

    sprintf(str_fmt, PIGSTY_NEXT_ENTRY
                     PIGSTY_NEW_ENTRY
                     "signature = \"%s\""
                     NEXT_PIGSTY, fmt);

    fprintf(pigsty, str_fmt, index);
}

static void init_pcap_rec_dumper_lookup_tables() {
    static int ltdone = 0;
    size_t c = 0, r = 0;
    size_t c_nr = 0, r_nr = 0;

    if (ltdone) {
        return;
    }

    c_nr = sizeof(g_pcap_rec_dumper_lt[0]) / sizeof(g_pcap_rec_dumper_lt[0][0]);
    r_nr = sizeof(g_pcap_rec_dumper_lt) / sizeof(g_pcap_rec_dumper_lt[0]);

    for (r = 0; r < r_nr; r++) {
        for (c = 0; c < c_nr; c++) {
            g_pcap_rec_dumper_lt[c][r] = generic_dumper;
        }
    }

    if (little_endian()) {
        g_pcap_rec_dumper_lt[0x00][0x08] = ip4_dumper;
        g_pcap_rec_dumper_lt[0x06][0x08] = arp_dumper;
        //g_pcap_rec_dumper_lt[0xdd][0x08] = ip6_dumper;
    } else {
        g_pcap_rec_dumper_lt[0x08][0x00] = ip4_dumper;
        g_pcap_rec_dumper_lt[0x08][0x06] = arp_dumper;
        //g_pcap_rec_dumper_lt[0x08][0xdd] = ip6_dumper;
    }

    r_nr = sizeof(g_pcap_rec_dumper_ip4tlayer_lt) / sizeof(g_pcap_rec_dumper_ip4tlayer_lt[0]);

    for (r = 0; r < r_nr; r++) {
        g_pcap_rec_dumper_ip4tlayer_lt[r] = generic_ip4tlayer_dumper;
    }

    g_pcap_rec_dumper_ip4tlayer_lt[0x01] = icmp_dumper;
    g_pcap_rec_dumper_ip4tlayer_lt[0x06] = tcp_dumper;
    g_pcap_rec_dumper_ip4tlayer_lt[0x11] = udp_dumper;

    //memset(g_pcap_rec_dumper_ip6tlayer_lt, generic_ip6tlayer_dumper, sizeof(g_pcap_rec_dumper_ip6tlayer_lt));

    //g_pcap_rec_dumper_ip6tlayer_lt[0x06] = tcp_dumper;
    //g_pcap_rec_dumper_ip6tlayer_lt[0x11] = udp_dumper;

    ltdone = 1;
}

static int pigsty_data(FILE *pigsty, const pcap_record_ctx *record, const int incl_ethframe) {
    pcap_rec_dumper pktdumper = NULL;
    unsigned short *ethtype = NULL;

    if (pigsty == NULL || record == NULL || record->data == NULL) {
        return 1;
    }

    ethtype = get_pkt_field("eth.type", record->data, record->hdr.incl_len, NULL);

    if (ethtype == NULL) {
        return 1;
    }

    pktdumper = g_pcap_rec_dumper_lt[(*ethtype) >> 8][(*ethtype) & 0xff];

    if (incl_ethframe || pktdumper == generic_dumper) {
        if (ethframe_dumper(pigsty, record) != 0) {
            return 1;
        }
    }

    if (pktdumper == NULL) {  // WARN(Santiago): It should never happen.
        return 1;
    }

    return pktdumper(pigsty, record);
}

static int ethframe_dumper(FILE *pigsty, const pcap_record_ctx *record) {
    struct pkt_field_dumper_ctx dumper[] = {
        { "eth.hwdst",   dump_maddr   },
        { "eth.hwsrc",   dump_maddr   },
        { "eth.type",    dump_xdata   }
        //  WARN(Santiago): Do not worry about the eth.payload field. The generic_dumper()
        //                  will spit it for us if needed.
    };

    if (pigsty == NULL || record == NULL || record->data == NULL) {
        return 1;
    }

    if (dumper_textsec(dumper, sizeof(dumper) / sizeof(dumper[0]), pigsty, record) != 0) {
        return 1;
    }

    fprintf(pigsty, PIGSTY_NEXT_ENTRY);

    return 0;
}

static int ip4_dumper(FILE *pigsty, const pcap_record_ctx *record) {
    struct pkt_field_dumper_ctx dumper[] = {
        { "ip.version",  dump_ddata   },
        { "ip.ihl",      dump_xdata   },
        { "ip.tos",      dump_xdata   },
        { "ip.tlen",     dump_ddata   },
        { "ip.id",       dump_xdata   },
        { "ip.offset",   dump_xdata   },
        { "ip.ttl",      dump_ddata   },
        { "ip.protocol", dump_ddata   },
        { "ip.checksum", dump_xdata   },
        { "ip.src",      dump_ip4addr },
        { "ip.dst",      dump_ip4addr }
    };
    size_t dumper_size = sizeof(dumper) / sizeof(dumper[0]);
    size_t d = 0;
    void *buffer = NULL;
    size_t buffer_size = 0;
    const char *field = NULL;
    unsigned char tlayer = 0xff;
    pcap_rec_dumper tlayerdumper = NULL;

    if (pigsty == NULL || record == NULL) {
        return 1;
    }

    for (d = 0; d < dumper_size; d++) {
        if (dumper[d].write != NULL) {
            field = dumper[d].field;
            buffer = get_pkt_field(field, record->data, record->hdr.incl_len, &buffer_size);

            if (buffer != NULL) {
                selwrite(dumper[d].write, pigsty, field, buffer, buffer_size);

                if (strcmp(field, "ip.protocol") == 0) {
                    tlayer = *(unsigned char *)buffer;
                }

                fprintf(pigsty, PIGSTY_NEXT_ENTRY);
            }
        }
    }

    tlayerdumper = g_pcap_rec_dumper_ip4tlayer_lt[tlayer];

    if (tlayerdumper == NULL) {  // WARN(Santiago): It should never happen.
        return 1;
    }

    return tlayerdumper(pigsty, record);
}

static int arp_dumper(FILE *pigsty, const pcap_record_ctx *record) {
    struct pkt_field_dumper_ctx dumper[] = {
        { "arp.hwtype", dump_xdata    },
        { "arp.ptype",  dump_xdata    },
        { "arp.hwlen",  dump_ddata    },
        { "arp.plen",   dump_ddata    },
        { "arp.opcode", dump_ddata    },
        { "arp.hwsrc",  dump_maddr    },
        { "arp.psrc",   NULL          },
        { "arp.hwdst",  dump_maddr    },
        { "arp.pdst",   NULL          }
    };
    size_t dumper_size = sizeof(dumper) / sizeof(dumper[0]);
    size_t d = 0;
    unsigned short ptype = 0;
    unsigned char plen = 0;
    void *buffer = NULL;
    size_t buffer_size = 0;
    const char *field = NULL;
    dump_writer write = NULL;

    if (pigsty == NULL || record == NULL) {
        return 1;
    }

    for (d = 0; d < dumper_size; d++) {
        field = dumper[d].field;
        buffer = get_pkt_field(field, record->data, record->hdr.incl_len, &buffer_size);

        if (buffer != NULL) {

            write = dumper[d].write;

            if (write == NULL) {
                if (strcmp(field, "arp.psrc") != 0 && strcmp(field, "arp.pdst") != 0) {
                    continue;
                }

                if (ptype == 0x0800 && plen == 0x4) {
                    selwrite(dump_ip4addr, pigsty, field, buffer, buffer_size);
                } else {
                    selwrite(dump_xstring, pigsty, field, buffer, buffer_size);
                }
            } else {
                selwrite(write, pigsty, field, buffer, buffer_size);

                if (strcmp(field, "arp.ptype") == 0) {
                    ptype = *(unsigned short *)buffer;
                    ptype = htons(ptype);
                } else if (strcmp(field, "arp.plen") == 0) {
                    plen = *(unsigned char *)buffer;
                }
            }

            if ((d + 1) != dumper_size) {
                fprintf(pigsty, PIGSTY_NEXT_ENTRY);
            }
        }

    }

    return 0;
}

static int generic_dumper(FILE *pigsty, const pcap_record_ctx *record) {
    if (pigsty == NULL || record == NULL) {
        return 1;
    }

    dump_xstring(pigsty, "eth.payload", record->data, record->hdr.incl_len);

    return 0;
}

static int icmp_dumper(FILE *pigsty, const pcap_record_ctx *record) {
    struct pkt_field_dumper_ctx dumper[] = {
        { "icmp.type",     dump_ddata   },
        { "icmp.code",     dump_ddata   },
        { "icmp.checksum", dump_xdata   },
        { "icmp.payload",  dump_xstring }
    };
    return dumper_textsec(dumper, sizeof(dumper) / sizeof(dumper[0]), pigsty, record);
}

static int tcp_dumper(FILE *pigsty, const pcap_record_ctx *record) {
    struct pkt_field_dumper_ctx dumper[] = {
        { "tcp.src",      dump_ddata    },
        { "tcp.dst",      dump_ddata    },
        { "tcp.seqno",    dump_xdata    },
        { "tcp.ackno",    dump_xdata    },
        { "tcp.size",     dump_ddata    },
        { "tcp.reserv",   dump_ddata    },
        { "tcp.flags",    dump_tcpflags },
        { "tcp.wsize",    dump_ddata    },
        { "tcp.checksum", dump_xdata    },
        { "tcp.urgp",     dump_xdata    },
        { "tcp.payload",  dump_string   }
    };
    return dumper_textsec(dumper, sizeof(dumper) / sizeof(dumper[0]), pigsty, record);
}

static int udp_dumper(FILE *pigsty, const pcap_record_ctx *record) {
    struct pkt_field_dumper_ctx dumper[] = {
        { "udp.src",      dump_ddata  },
        { "udp.dst",      dump_ddata  },
        { "udp.size",     dump_ddata  },
        { "udp.checksum", dump_xdata  },
        { "udp.payload",  dump_string }
    };
    return dumper_textsec(dumper, sizeof(dumper) / sizeof(dumper[0]), pigsty, record);
}

static int dumper_textsec(struct pkt_field_dumper_ctx *dumper, size_t dumper_size, FILE *pigsty, const pcap_record_ctx *record) {
    size_t d = 0;
    void *buffer = NULL;
    size_t buffer_size = 0;
    const char *field = NULL;

    if (pigsty == NULL || record == NULL || dumper == NULL || dumper_size == 0) {
        return 1;
    }

    for (d = 0; d < dumper_size; d++) {
        field = dumper[d].field;

        buffer = get_pkt_field(field, record->data, record->hdr.incl_len, &buffer_size);

        if (buffer != NULL) {
            selwrite(dumper[d].write, pigsty, field, buffer, buffer_size);

            if ((d + 1) != dumper_size) {
                fprintf(pigsty, PIGSTY_NEXT_ENTRY);
            }
        }
    }

    return 0;
}

static int generic_ip4tlayer_dumper(FILE *pigsty, const pcap_record_ctx *record) {
    if (pigsty == NULL || record == NULL) {
        return 1;
    }

    dump_xstring(pigsty, "ip.payload", record->data, record->hdr.incl_len);

    return 0;
}

static void dump_xdata(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size) {
    char temp[20] = "";
    const unsigned char *bp = NULL;
    const unsigned char *bp_end = NULL;

    if (pigsty == NULL || field == NULL || buffer == NULL || buffer_size == 0) {
        return;
    }

    fprintf(pigsty, PIGSTY_NEW_ENTRY "%s = 0x", field);

    bp = buffer;
    bp_end = bp + buffer_size;
    while (bp != bp_end) {
        sprintf(temp, "%.2X", *bp);
        fprintf(pigsty, "%s", temp);
        bp++;
    }
}

static void dump_ddata(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size) {
    char temp[20] = "";

    if (pigsty == NULL || field == NULL || buffer == NULL || buffer_size == 0) {
        return;
    }

    switch (buffer_size) {
        case sizeof(unsigned char):
            sprintf(temp, "%d", *(unsigned char *)buffer);
            break;

        case sizeof(unsigned short):
            sprintf(temp, "%d", htons(*(unsigned short *)buffer));
            break;

        case sizeof(unsigned int):
            sprintf(temp, "%d", htonl(*(unsigned int *)buffer));
            break;

        default:
            return;
    }

    fprintf(pigsty, PIGSTY_NEW_ENTRY "%s = %s", field, temp);
}

static void dump_ip4addr(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size) {

    if (pigsty == NULL || field == NULL || buffer == NULL || buffer_size != 4) {
        return;
    }

    fprintf(pigsty, PIGSTY_NEW_ENTRY "%s = %d.%d.%d.%d", field, *(buffer), *(buffer + 1), *(buffer + 2), *(buffer + 3));
}

static void dump_xstring(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size) {
    const unsigned char *bp = NULL;
    const unsigned char *bp_end = NULL;
    char temp[20] = "";

    if (pigsty == NULL || field == NULL || buffer == NULL || buffer_size == 0) {
        return;
    }

    bp = buffer;
    bp_end = bp + buffer_size;

    fprintf(pigsty, PIGSTY_NEW_ENTRY "%s = \"", field);

    while (bp != bp_end) {
        sprintf(temp, "\\x%.2x", *bp);
        fprintf(pigsty, "%s", temp);
        bp++;
    }

    fprintf(pigsty, "\"");
}

static void dump_string(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size) {
    const unsigned char *bp = NULL;
    const unsigned char *bp_end = NULL;
    char temp[20] = "";
    int lxc = 0;

    if (pigsty == NULL || field == NULL || buffer == NULL || buffer_size == 0) {
        return;
    }

    bp = buffer;
    bp_end = bp + buffer_size;

    fprintf(pigsty, PIGSTY_NEW_ENTRY "%s = \"", field);

    while (bp != bp_end) {

        if (isprint(*bp) && *bp != '\\') {
            if (!isxdigit(*bp)) {
                fprintf(pigsty, "%c", *bp);
                lxc = 0;
            } else {
                if (lxc) {
                    sprintf(temp, "\\x%.2x", *bp);
                    fprintf(pigsty, "%s", temp);
                    lxc = 1;
                } else {
                    fprintf(pigsty, "%c", *bp);
                    lxc = 0;
                }
            }
        } else if (*bp == '\t') {
            fprintf(pigsty, "\\t");
            lxc = 0;
        } else if (*bp == '\n') {
            fprintf(pigsty, "\\n");
            lxc = 0;
        } else if (*bp == '\r') {
            fprintf(pigsty, "\\r");
            lxc = 0;
        } else if (*bp == '\\') {
            fprintf(pigsty, "\\\\");
            lxc = 0;
        } else if (*bp == '"') {
            fprintf(pigsty, "\\\"");
            lxc = 0;
        } else {
            sprintf(temp, "\\x%.2x", *bp);
            fprintf(pigsty, "%s", temp);
            lxc = 1;
        }

        bp++;
    }

    fprintf(pigsty, "\"");
}

static void dump_tcpflags(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size) {
    char *data = NULL;
    struct dump_program_instruction_set {
        const char *option;
        const char *field;
        const char *ntok;
    };
    struct dump_program_instruction_set dump_task[] = {
        { "tcp-urg", "tcp.urg", PIGSTY_NEXT_ENTRY },
        { "tcp-ack", "tcp.ack", PIGSTY_NEXT_ENTRY },
        { "tcp-psh", "tcp.psh", PIGSTY_NEXT_ENTRY },
        { "tcp-rst", "tcp.rst", PIGSTY_NEXT_ENTRY },
        { "tcp-syn", "tcp.syn", PIGSTY_NEXT_ENTRY },
        { "tcp-fin", "tcp.fin", ""                }
    };
    size_t dump_task_nr = sizeof(dump_task) / sizeof(dump_task[0]);
    size_t d;

    for (d = 0; d < dump_task_nr; d++) {
        data = get_option(dump_task[d].option, NULL);
        if (data != NULL) {
            fprintf(pigsty, PIGSTY_NEW_ENTRY "%s = %s%s", dump_task[d].field, data, dump_task[d].ntok);
        } else {
            dump_tcpflag(pigsty, dump_task[d].field, buffer, buffer_size, dump_task[d].ntok);
        }
    }
}

static void dump_tcpflag(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size, const char *ntok) {
    int rsh = -1;

    if (pigsty == NULL || field == NULL || buffer == NULL || buffer_size == 0) {
        return;
    }

    if (strcmp(field, "tcp.urg") == 0) {
        rsh = 5;
    } else if (strcmp(field, "tcp.ack") == 0) {
        rsh = 4;
    } else if (strcmp(field, "tcp.psh") == 0) {
        rsh = 3;
    } else if (strcmp(field, "tcp.rst") == 0) {
        rsh = 2;
    } else if (strcmp(field, "tcp.syn") == 0) {
        rsh = 1;
    } else if (strcmp(field, "tcp.fin") == 0) {
        rsh = 0;
    }

    if (rsh != -1) {
        fprintf(pigsty, PIGSTY_NEW_ENTRY "%s = %d%s", field, (((*buffer) >> rsh) & 0x1), ntok);
    }
}

static void dump_maddr(FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size) {
    const unsigned char *bp = NULL;
    const unsigned char *bp_end = NULL;

    if (pigsty == NULL || field == NULL || buffer == NULL || buffer_size == 0) {
        return;
    }

    bp = buffer;
    bp_end = bp + buffer_size;

    fprintf(pigsty, PIGSTY_NEW_ENTRY "%s = \"", field);

    while (bp != bp_end) {
        fprintf(pigsty, "%.2X", *bp);
        bp++;
        if (bp != bp_end) {
            fprintf(pigsty, ":");
        }
    }

    fprintf(pigsty, "\"");
}

static void selwrite(dump_writer writer, FILE *pigsty, const char *field, const unsigned char *buffer, const size_t buffer_size) {
    char label[255] = "";
    char *data = NULL;

    if (field == NULL || pigsty == NULL || buffer == NULL || buffer_size == 0) {
        return;
    }

    if (strcmp(field, "tcp.flags") != 0) {
        get_option_label_from_field(label, field);

        data = get_option(label, NULL);

        if (data != NULL) {
            fprintf(pigsty, PIGSTY_NEW_ENTRY "%s = %s", field, data);
            return;
        }
    }

    if (writer == NULL) { //  WARN(Santiago): It should never happen.
        return;
    }

    writer(pigsty, field, buffer, buffer_size);
}

void get_option_label_from_field(char *option, const char *field) {
    const char *fp = NULL;
    char *op = NULL;

    if (field == NULL || option == NULL) {
        return;
    }

    fp  = field;
    op = option;

    while (*fp != 0) {
        if (*fp == '.') {
            *op = '-';
        } else {
            *op = *fp;
        }

        fp++;
        op++;
    }

    *op = 0;
}

