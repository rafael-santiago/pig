/*
 *                                Copyright (C) 2015 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "types.h"
#include "pigsty.h"
#include "lists.h"
#include "oink.h"
#include "linux/native_arp.h"
#include "arp.h"
#include "options.h"
#include <stdio.h>
#include <string.h>
#include <signal.h>

static int g_should_exit = 0;

static void sigint_watchdog(int signr);

static pigsty_entry_ctx *load_signatures(const char *signatures);

static int run_pig_run();

static int is_targets_option_required(const pigsty_entry_ctx *entries);

static void sigint_watchdog(int signr) {
    g_should_exit = 1;
}

static pigsty_entry_ctx *load_signatures(const char *signatures) {
    pigsty_entry_ctx *sig_entries = NULL;
    const char *sp = NULL;
    char curr_file_path[8192] = "";
    char *cfp = NULL;
    char *no_echo = get_option("no-echo", NULL);
    sp = signatures;
    cfp = &curr_file_path[0];
    while (*sp != 0) {
        if (*sp != ',' && *(sp + 1) != 0) {
            *cfp = *sp;
            cfp++;
        } else {
            if (*(sp + 1) == 0) {
                if (*sp != ',') {
                    *cfp = *sp;
                    cfp++;
                }
            }
            *cfp = '\0';
            if (no_echo == NULL) {
                printf("pig INFO: loading \"%s\"...\n", curr_file_path);
            }
            sig_entries = load_pigsty_data_from_file(sig_entries, curr_file_path);
            if (sig_entries == NULL) {
                if (no_echo == NULL) {
                    printf("pig INFO: load failure.\n");
                }
                break;
            }
            if (no_echo == NULL) {
                printf("pig INFO: load success.\n");
            }
            cfp = &curr_file_path[0];
        }
        sp++;
    }
    return sig_entries;
}

static pig_target_addr_ctx *parse_targets(const char *targets) {
    pig_target_addr_ctx *addr = NULL;
    const char *tp = NULL;
    char range[0xff];
    size_t r = 0;
    if (targets == NULL) {
        return NULL;
    }
    memset(range, 0, sizeof(range));
    r = 0;
    for (tp = targets; *tp != 0; tp++) {
        if (*tp == ',' || *(tp + 1) == 0) {
            if (*(tp + 1) == 0) {
                range[r] = *tp;
            }
            if (get_range_type(range) == kNone) {
                printf("pig WARNING: the IP range \"%s\" seems invalid... it will be skipped.\n", range);
            } else {
                addr = add_target_addr_to_pig_target_addr(addr, range);
            }
            r = 0;
            memset(range, 0, sizeof(range));
        } else {
            range[r] = *tp;
            r = (r + 1) % sizeof(range);
        }
    }
    return addr;
}

static int run_pig_run() {
    int timeo = 10000;
    pigsty_entry_ctx *pigsty = NULL;
    size_t signatures_count = 0, addr_count = 0;
    pigsty_entry_ctx *signature = NULL, *sp = NULL;
    pig_target_addr_ctx *addr = NULL, *addr_p = NULL;
    pig_hwaddr_ctx *hwaddr = NULL;
    int sockfd = -1;
    int retval = 0;
    int should_be_quiet = 0;
    unsigned int nt_mask_addr[4] = { 0, 0, 0, 0 };
    unsigned char *gw_hwaddr = NULL, *temp = NULL;
    in_addr_t gw_in_addr = 0;
    char *signatures = NULL;
    char *timeout = NULL;
    char *tp = NULL;
    char *targets = NULL;
    char *gw_addr = NULL;
    char *loiface = NULL;
    char *nt_mask = NULL;
    char *single_test = NULL;
    char *no_gateway = NULL;
    signatures = get_option("signatures", NULL);
    if (signatures == NULL) {
        printf("pig ERROR: --signatures option is missing.\n");
        return 1;
    }
    no_gateway = get_option("no-gateway", NULL);
    if (no_gateway == NULL) {
        gw_addr = get_option("gateway", NULL);
        if (gw_addr == NULL) {
            printf("pig ERROR: --gateway option is missing.\n");
            return 1;
        }
        nt_mask = get_option("net-mask", NULL);
        if (nt_mask == NULL) {
            printf("pig ERROR: --net-mask option is missing.\n");
            return 1;
        }
    }
    loiface = get_option("lo-iface", NULL);
    if (loiface == NULL) {
        printf("pig ERROR: --lo-iface option is missing.\n");
        return 1;
    }
    timeout = get_option("timeout", NULL);
    if (timeout != NULL) {
        for (tp = timeout; *tp != 0; tp++) {
            if (!isdigit(*tp)) {
                printf("pig ERROR: an invalid timeout value was supplied.\n");
                return 1;
            }
        }
    }
    should_be_quiet = (get_option("no-echo", NULL) != NULL);
    targets = get_option("targets", NULL);
    single_test = get_option("single-test", NULL);
    if (timeout != NULL) {
        timeo = atoi(timeout);
    }
    timeo = timeo * 1000;
    if (!should_be_quiet) {
        printf("pig INFO: starting up pig engine...\n\n");
    }
    sockfd = init_raw_socket(loiface);
    if (sockfd == -1) {
        printf("pig PANIC: unable to create the socket.\npig ERROR: aborted.\n");
        return 1;
    }
    pigsty = load_signatures(signatures);
    if (pigsty == NULL) {
        printf("pig ERROR: aborted.\n");
        deinit_raw_socket(sockfd);
        return 1;
    }
    if (targets != NULL) {
        if (!should_be_quiet) {
            printf("\npig INFO: parsing the supplied targets...\n");
            printf("pig INFO: all targets were parsed.\n");
        }
        addr = parse_targets(targets);
    }
    if (is_targets_option_required(pigsty) && addr == NULL) {
        printf("pig PANIC: --targets option is required by some loaded signatures.\n");
        deinit_raw_socket(sockfd);
        del_pigsty_entry(pigsty);
        return 1;
    }
    signatures_count = get_pigsty_entry_count(pigsty);
    if (!should_be_quiet) {
        printf("\npig INFO: done (%d signature(s) read).\n\n", signatures_count);
    }
    if (no_gateway == NULL && nt_mask == NULL) {
        printf("\npig PANIC: --net-mask option is required.\n");
        deinit_raw_socket(sockfd);
        del_pigsty_entry(pigsty);
        return 1;
    }
    //  WARN(Santiago): by now IPv4 only.
    if (no_gateway == NULL && verify_ipv4_addr(nt_mask) == 0) {
        printf("pig PANIC: --net-mask has an invalid ip address.\n");
        deinit_raw_socket(sockfd);
        del_pigsty_entry(pigsty);
        return 1;
    }
    if (no_gateway == NULL) {
        nt_mask_addr[0] = htonl(inet_addr(nt_mask));
        if (gw_addr != NULL && loiface != NULL) {
            gw_in_addr = inet_addr(gw_addr);
            temp = get_mac_by_addr(gw_in_addr, loiface, 2);
            if (!should_be_quiet && temp != NULL) {
                gw_hwaddr = mac2byte(temp, strlen(temp));
                printf("pig INFO: the gateway's physical address is \"%s\"...\n"
                       "pig INFO: the local interface is \"%s\"...\n"
                       "pig INFO: the network mask is \"%s\"...\n\n", temp, loiface, nt_mask);
                free(temp);
            }
        }
    } else {
        printf("pig INFO: the local interface is \"%s\"...\n", loiface);
    }
    if (no_gateway != NULL || gw_hwaddr != NULL) {
        signature = get_pigsty_entry_by_index(rand() % signatures_count, pigsty);
        if (single_test == NULL) {
            while (!g_should_exit) {
                if (signature == NULL) {
                    continue; //  WARN(Santiago): It should never happen. However... Sometimes... The World tends to be a rather weird place.
                }
                if (oink(signature, &hwaddr, addr, sockfd, gw_hwaddr, nt_mask_addr, loiface) != -1) {
                    if (!should_be_quiet) {
                        printf("pig INFO: a packet based on signature \"%s\" was sent.\n", signature->signature_name);
                    }
                    usleep(timeo);
                }
                signature = get_pigsty_entry_by_index(rand() % signatures_count, pigsty);
            }
        } else {
            retval = (oink(signature, &hwaddr, addr, sockfd, gw_hwaddr, nt_mask_addr, loiface) != -1 ? 0 : 1);
            if (retval == 0) {
                if (!should_be_quiet) {
                    printf("pig INFO: a packet based on signature \"%s\" was sent.\n", signature->signature_name);
                }
            }
        }
        free(gw_hwaddr);
    } else {
        printf("\npig PANIC: unable to get the gateway's physical address.\n");
    }
    del_pigsty_entry(pigsty);
    del_pig_target_addr(addr);
    del_pig_hwaddr(hwaddr);
    deinit_raw_socket(sockfd);
    return retval;
}

static int is_targets_option_required(const pigsty_entry_ctx *entries) {
    const pigsty_conf_set_ctx *cp = NULL;
    const pigsty_entry_ctx *ep = NULL;
    for (ep = entries; ep != NULL; ep = ep->next) {
        for (cp = ep->conf; cp != NULL; cp = cp->next) {
            if (cp->field->index == kIpv4_src || cp->field->index == kIpv4_dst) {
                if (cp->field->dsize > 4 && strcmp(cp->field->data, "user-defined-ip") == 0) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    char *no_echo = get_option("no-echo", NULL);
    int exit_code = 1;
    register_options(argc, argv);
    if (get_option("version", NULL) != NULL) {
        printf("pig v%s\n", PIG_VERSION);
        return 0;
    }
    if (argc > 1) {
        signal(SIGINT, sigint_watchdog);
        signal(SIGTERM, sigint_watchdog);
        srand(time(0));
        exit_code = run_pig_run();
        if (no_echo == NULL && exit_code == 0) {
            printf("\npig INFO: exiting... please wait...\npig INFO: pig has gone.\n");
        }
    } else {
        printf("usage: %s --signatures=file.0,file.1,(...),file.n --gateway=<gateway address> --net-mask=<network mask> --lo-iface=<network interface> [--timeout=<in msecs> --no-echo --targets=n.n.n.n,n.*.*.*,n.n.n.n/n]\n", argv[0]);
    }
    return exit_code;
}
