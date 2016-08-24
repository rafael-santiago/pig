/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "pktcraft.h"
#include "types.h"
#include "pigsty.h"
#include "lists.h"
#include "oink.h"
#include "sock.h"
#include "linux/native_arp.h"
#include "arp.h"
#include "netmask.h"
#include "options.h"
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

static int g_pig_out = 0; //  :)

struct pktcraft_options_ctx {
    char *signatures;
    char *targets;
    char *gw_addr;
    char *loiface;
    char *nt_mask;
    char *single_test;
    char *no_gateway;
    int should_be_quiet;
    int timeo;
};

typedef int (*pig_pktcrafter)(const pigsty_entry_ctx *pigsty,
                              const size_t signatures_count,
                              pig_hwaddr_ctx *hwaddr,
                              const pig_target_addr_ctx *addr,
                              const int sockfd,
                              const unsigned char *gw_hwaddr,
                              const unsigned int nt_mask_addr[4],
                              const struct pktcraft_options_ctx user_options);

static pigsty_entry_ctx *load_signatures(const char *signatures);

static pig_target_addr_ctx *parse_targets(const char *targets);

static int is_targets_option_required(const pigsty_entry_ctx *entries);

static int parse_pktcraft_options(struct pktcraft_options_ctx *options);

static int exec_pktcraft(const struct pktcraft_options_ctx user_options);

static int singletest_pktcrafter(const pigsty_entry_ctx *pigsty,
                                 const size_t signatures_count,
                                 pig_hwaddr_ctx *hwaddr,
                                 const pig_target_addr_ctx *addr,
                                 const int sockfd,
                                 const unsigned char *gw_hwaddr,
                                 const unsigned int nt_mask_addr[4],
                                 const struct pktcraft_options_ctx user_options);

static int endless_pktcrafter(const pigsty_entry_ctx *pigsty,
                              const size_t signatures_count,
                              pig_hwaddr_ctx *hwaddr,
                              const pig_target_addr_ctx *addr,
                              const int sockfd,
                              const unsigned char *gw_hwaddr,
                              const unsigned int nt_mask_addr[4],
                              const struct pktcraft_options_ctx user_options);

static int sequential_pktcrafter(const pigsty_entry_ctx *pigsty,
                                 const size_t signatures_count,
                                 pig_hwaddr_ctx *hwaddr,
                                 const pig_target_addr_ctx *addr,
                                 const int sockfd,
                                 const unsigned char *gw_hwaddr,
                                 const unsigned int nt_mask_addr[4],
                                 const struct pktcraft_options_ctx user_options);

static int random_pktcrafter(const pigsty_entry_ctx *pigsty,
                             const size_t signatures_count,
                             pig_hwaddr_ctx *hwaddr,
                             const pig_target_addr_ctx *addr,
                             const int sockfd,
                             const unsigned char *gw_hwaddr,
                             const unsigned int nt_mask_addr[4],
                             const struct pktcraft_options_ctx user_options);

static int single_pktcraft(const pigsty_entry_ctx *signature,
                           pig_hwaddr_ctx *hwaddr,
                           const pig_target_addr_ctx *addr,
                           const int sockfd,
                           const unsigned char *gw_hwaddr,
                           const unsigned int nt_mask_addr[4],
                           const struct pktcraft_options_ctx user_options);

void stop_pktcraft() {
    g_pig_out = 1;
}

int pktcraft() {
    char *option = NULL;
    struct pktcraft_options_ctx user_options;
    int exit_code = 0;

    option = get_option("help", NULL);

    if (option != NULL) {
        return pktcraft_help();
    }

    if ((exit_code = parse_pktcraft_options(&user_options)) != 0) {
        return exit_code;
    }

    return exec_pktcraft(user_options);
}

int pktcraft_help() {
    printf("usage: pig --signatures=file.0,file.1,(...),file.n "
           "--gateway=<gateway address> --net-mask=<network mask> "
           "--lo-iface=<network interface> [--timeout=<in msecs> "
           "--no-echo --targets=n.n.n.n,n.*.*.*,n.n.n.n/n --no-gateway --loop=<random|sequential>]\n\n"
           "*** If you want to know more about some sub-task you should try: \"pig --sub-task=<name> --help\".\n"
           "    Do not you know any sub-task name? Welcome newbie! It is time to read some documentation: \"man pig\".\n___\n"
           "pig is Copyright (C) 2015-2016 by Rafael Santiago.\n\n"
           "Bug reports, feedback, etc: <voidbrainvoid@gmail.com> or <https://github.com/rafael-santiago/pig/issues>\n");
    return 0;
}

static int parse_pktcraft_options(struct pktcraft_options_ctx *options) {
    char *data = NULL;
    char *dp = NULL;

    if (options == NULL) {
        return 1;
    }

    options->signatures = get_option("signatures", NULL);

    if (options->signatures == NULL) {
        printf("pig ERROR: --signatures option is missing.\n");
        return 1;
    }

    options->no_gateway = get_option("no-gateway", NULL);
    if (options->no_gateway == NULL) {
        options->gw_addr = get_option("gateway", NULL);
        if (options->gw_addr == NULL) {
            printf("pig ERROR: --gateway option is missing.\n");
            return 1;
        }

        options->nt_mask = get_option("net-mask", NULL);
        if (options->nt_mask == NULL) {
            printf("pig ERROR: --net-mask option is missing.\n");
            return 1;
        }
    }

    options->loiface = get_option("lo-iface", NULL);
    if (options->loiface == NULL) {
        printf("pig ERROR: --lo-iface option is missing.\n");
        return 1;
    }

    data = get_option("timeout", NULL);
    if (data != NULL) {
        for (dp = data; *dp != 0; dp++) {
            if (!isdigit(*dp)) {
                printf("pig ERROR: an invalid timeout value was supplied.\n");
                return 1;
            }
        }
    }

    options->timeo = ((data != NULL) ? atoi(data) : 10000) * 1000;

    options->should_be_quiet = (get_option("no-echo", NULL) != NULL);
    options->targets = get_option("targets", NULL);
    options->single_test = get_option("single-test", NULL);

    return 0;
}

static int exec_pktcraft(const struct pktcraft_options_ctx user_options) {
    pigsty_entry_ctx *pigsty = NULL;
    size_t signatures_count = 0, addr_count = 0;
    pigsty_entry_ctx *signature = NULL, *sp = NULL;
    pig_target_addr_ctx *addr = NULL, *addr_p = NULL;
    pig_hwaddr_ctx *hwaddr = NULL;
    int sockfd = -1;
    int exit_code = 1;
    int should_be_quiet = 0;
    unsigned int nt_mask_addr[4] = { 0, 0, 0, 0 };
    unsigned char *gw_hwaddr = NULL;
    char *temp = NULL;
    in_addr_t gw_in_addr = 0;
    pig_pktcrafter pktcrafter = random_pktcrafter;

    if (!user_options.should_be_quiet) {
        printf("pig INFO: starting up pig engine...\n\n");
    }

    sockfd = init_raw_socket(user_options.loiface);

    if (sockfd == -1) {
        printf("pig PANIC: unable to create the socket.\npig ERROR: aborted.\n");
        return 1;
    }

    pigsty = load_signatures(user_options.signatures);

    if (pigsty == NULL) {
        printf("pig ERROR: aborted.\n");
        deinit_raw_socket(sockfd);
        return 1;
    }

    if (user_options.targets != NULL) {
        if (!user_options.should_be_quiet) {
            printf("\npig INFO: parsing the supplied targets...\n");
            printf("pig INFO: all targets were parsed.\n");
        }
        addr = parse_targets(user_options.targets);
    }

    if (is_targets_option_required(pigsty) && addr == NULL) {
        printf("pig PANIC: --targets option is required by some loaded signatures.\n");
        deinit_raw_socket(sockfd);
        del_pigsty_entry(pigsty);
        return 1;
    }

    signatures_count = get_pigsty_entry_count(pigsty);

    if (!user_options.should_be_quiet) {
        printf("\npig INFO: done [%d signature(s) read].\n\n", signatures_count);
    }

    if (user_options.no_gateway == NULL && user_options.nt_mask == NULL) {
        printf("\npig PANIC: --net-mask option is required.\n");
        deinit_raw_socket(sockfd);
        del_pigsty_entry(pigsty);
        return 1;
    }

    //  WARN(Santiago): by now IPv4 only.
    if (user_options.no_gateway == NULL && verify_ipv4_addr(user_options.nt_mask) == 0) {
        printf("pig PANIC: --net-mask has an invalid ip address.\n");
        deinit_raw_socket(sockfd);
        del_pigsty_entry(pigsty);
        return 1;
    }

    if (user_options.no_gateway == NULL) {
        nt_mask_addr[0] = htonl(inet_addr(user_options.nt_mask));
        if (user_options.gw_addr != NULL && user_options.loiface != NULL) {
            gw_in_addr = inet_addr(user_options.gw_addr);
            temp = get_mac_by_addr(gw_in_addr, user_options.loiface, 2);
            gw_hwaddr = mac2byte(temp, strlen(temp));
            if (!user_options.should_be_quiet && temp != NULL) {
                printf("pig INFO: the gateway's physical address is \"%s\"...\n"
                       "pig INFO: the local interface is \"%s\"...\n"
                       "pig INFO: the network mask is \"%s\"...\n\n", temp, user_options.loiface, user_options.nt_mask);
            }
            free(temp);
        }
    } else {
        printf("pig INFO: the local interface is \"%s\"...\n", user_options.loiface);
    }

    if (user_options.no_gateway != NULL || gw_hwaddr != NULL) {
        if (user_options.single_test == NULL) {
            pktcrafter = endless_pktcrafter;
        } else {
            pktcrafter = singletest_pktcrafter;
        }
    } else {
        printf("\npig PANIC: unable to get the gateway's physical address.\n");
        return 1;
    }

    exit_code = pktcrafter(pigsty, signatures_count, hwaddr, addr, sockfd, gw_hwaddr, nt_mask_addr, user_options);

    free(gw_hwaddr);

    del_pigsty_entry(pigsty);
    del_pig_target_addr(addr);
    del_pig_hwaddr(hwaddr);
    deinit_raw_socket(sockfd);

    return exit_code;
}

static int singletest_pktcrafter(const pigsty_entry_ctx *pigsty,
                                 const size_t signatures_count,
                                 pig_hwaddr_ctx *hwaddr,
                                 const pig_target_addr_ctx *addr,
                                 const int sockfd,
                                 const unsigned char *gw_hwaddr,
                                 const unsigned int nt_mask_addr[4],
                                 const struct pktcraft_options_ctx user_options) {

    return single_pktcraft(get_pigsty_entry_by_index(rand() % signatures_count, pigsty),
                           hwaddr, addr, sockfd, gw_hwaddr, nt_mask_addr, user_options);
}

static int endless_pktcrafter(const pigsty_entry_ctx *pigsty,
                              const size_t signatures_count,
                              pig_hwaddr_ctx *hwaddr,
                              const pig_target_addr_ctx *addr,
                              const int sockfd,
                              const unsigned char *gw_hwaddr,
                              const unsigned int nt_mask_addr[4],
                              const struct pktcraft_options_ctx user_options) {
    char *loop = NULL;
    pig_pktcrafter pktcrafter = NULL;

    loop = get_option("loop", "random");

    if (strcmp(loop, "random") == 0) {
        pktcrafter = random_pktcrafter;
    } else if (strcmp(loop, "sequential") == 0) {
        pktcrafter = sequential_pktcrafter;
    } else {
        printf("pig ERROR: --loop has unknown mode \"%s\".\n", loop);
        return 1;
    }

    return pktcrafter(pigsty, signatures_count, hwaddr, addr, sockfd, gw_hwaddr, nt_mask_addr, user_options);
}

static int sequential_pktcrafter(const pigsty_entry_ctx *pigsty,
                                 const size_t signatures_count,
                                 pig_hwaddr_ctx *hwaddr,
                                 const pig_target_addr_ctx *addr,
                                 const int sockfd,
                                 const unsigned char *gw_hwaddr,
                                 const unsigned int nt_mask_addr[4],
                                 const struct pktcraft_options_ctx user_options) {

    const pigsty_entry_ctx *p = pigsty;
    int retval = 0;

    while (!g_pig_out) {

        retval = single_pktcraft(p, hwaddr, addr, sockfd, gw_hwaddr, nt_mask_addr, user_options);

        p = (p->next != NULL) ? p->next : pigsty;

        usleep(user_options.timeo);
    }

    if (!user_options.should_be_quiet) {
        printf("\npig INFO: exiting... please wait...\npig INFO: pig has gone.\n");
    }

    return retval;
}

static int random_pktcrafter(const pigsty_entry_ctx *pigsty,
                             const size_t signatures_count,
                             pig_hwaddr_ctx *hwaddr,
                             const pig_target_addr_ctx *addr,
                             const int sockfd,
                             const unsigned char *gw_hwaddr,
                             const unsigned int nt_mask_addr[4],
                             const struct pktcraft_options_ctx user_options) {

    const pigsty_entry_ctx *signature = NULL;
    int retval = 0;

    srand(time(0));

    while (!g_pig_out) {
        signature = get_pigsty_entry_by_index(rand() % signatures_count, pigsty);

        if (signature == NULL) {
            continue; //  WARN(Santiago): It should never happen.
        }

        retval = single_pktcraft(signature, hwaddr, addr, sockfd, gw_hwaddr, nt_mask_addr, user_options);

        usleep(user_options.timeo);
    }

    if (!user_options.should_be_quiet) {
        printf("\npig INFO: exiting... please wait...\npig INFO: pig has gone.\n");
    }

    return retval;
}

static int single_pktcraft(const pigsty_entry_ctx *signature,
                           pig_hwaddr_ctx *hwaddr,
                           const pig_target_addr_ctx *addr,
                           const int sockfd,
                           const unsigned char *gw_hwaddr,
                           const unsigned int nt_mask_addr[4],
                           const struct pktcraft_options_ctx user_options) {

    int retval = (oink(signature, &hwaddr, addr, sockfd, gw_hwaddr, nt_mask_addr, user_options.loiface) != -1 ? 0 : 1);
    if (retval == 0) {
        if (!user_options.should_be_quiet) {
            printf("pig INFO: a packet based on signature \"%s\" was sent.\n", signature->signature_name);
        }
    }
    return retval;
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

static int is_targets_option_required(const pigsty_entry_ctx *entries) {
    const pigsty_conf_set_ctx *cp = NULL;
    const pigsty_entry_ctx *ep = NULL;
    for (ep = entries; ep != NULL; ep = ep->next) {
        for (cp = ep->conf; cp != NULL; cp = cp->next) {
            if (cp->field->index == kIpv4_src || cp->field->index == kIpv4_dst ||
                cp->field->index == kArp_psrc || cp->field->index == kArp_pdst) {
                if (cp->field->dsize > 4 && strcmp(cp->field->data, "user-defined-ip") == 0) {
                    return 1;
                }
            }
        }
    }
    return 0;
}
