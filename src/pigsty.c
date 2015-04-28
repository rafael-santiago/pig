#include "pigsty.h"
#include "memory.h"
#include "lists.h"
#include <stdio.h>
#include <string.h>

#define is_pigsty_blank(c) ( (c) == ' ' || (c) == '\t' || (c) == '\n' || (c) == '\r' )

#define is_pigsty_comment(c) ( (c) == '#' )

static char *get_pigsty_file_data(const char *filepath);

static int compile_next_buffered_pigsty_entry(char *buffer, char **next);

static int compile_pigsty_buffer(const char *data);

static char *skip_pigsty_comment(char *buffer);

static char *skip_pigsty_blank(char *buffer);

static char *get_next_pigsty_word(char *buffer, char **next);

struct signature_fields {
    const char *label;
    const pig_field_t index;
    int (*verifier)(const char *data);
};

static int verify_ip_version(const char *buffer);

static int verify_string(const char *buffer);

static int verify_u1(const char *buffer);

static int verify_u3(const char *buffer);

static int verify_u4(const char *buffer);

static int verify_u6(const char *buffer);

static int verify_u8(const char *buffer);

static int verify_u13(const char *buffer);

static int verify_u16(const char *buffer);

static int verify_u32(const char *buffer);

static int verify_ipv4_addr(const char *buffer);

static get_pigsty_field_index(const char *field);

static struct signature_fields SIGNATURE_FIELDS[] = {
    {  "ip.version",  kIpv4_version, verify_ip_version},
    {      "ip.ihl",      kIpv4_ihl,         verify_u4},
    {      "ip.tos",      kIpv4_tos,         verify_u8},
    {     "ip.tlen",     kIpv4_tlen,        verify_u16},
    {       "ip.id",       kIpv4_id,        verify_u16},
    {    "ip.flags",    kIpv4_flags,         verify_u3},
    {   "ip.offset",   kIpv4_offset,        verify_u13},
    {      "ip.ttl",      kIpv4_ttl,         verify_u8},
    { "ip.protocol", kIpv4_protocol,         verify_u8},
    { "ip.checksum", kIpv4_checksum,        verify_u16},
    {      "ip.src",      kIpv4_src,  verify_ipv4_addr},
    {      "ip.dst",      kIpv4_dst,  verify_ipv4_addr},
    {     "tcp.src",       kTcp_src,        verify_u16},
    {     "tcp.dst",       kTcp_dst,        verify_u16},
    {   "tcp.seqno",       kTcp_seq,        verify_u32},
    {   "tcp.ackno",     kTcp_ackno,        verify_u32},
    {    "tcp.size",      kTcp_size,         verify_u4},
    {  "tcp.reserv",    kTcp_reserv,         verify_u6},
    {     "tcp.urg",       kTcp_urg,         verify_u1},
    {     "tcp.ack",       kTcp_ack,         verify_u1},
    {     "tcp.psh",       kTcp_psh,         verify_u1},
    {     "tcp.rst",       kTcp_rst,         verify_u1},
    {     "tcp.syn",       kTcp_syn,         verify_u1},
    {     "tcp.fin",       kTcp_fin,         verify_u1},
    {   "tcp.wsize",     kTcp_wsize,        verify_u16},
    {"tcp.checksum",  kTcp_checksum,        verify_u16},
    {    "tcp.urgp",      kTcp_urgp,        verify_u16},
    { "tcp.payload",   kTcp_payload,              NULL},
    {     "udp.src",       kUdp_src,        verify_u16},
    {     "udp.dst",       kUdp_dst,        verify_u16},
    {    "udp.size",      kUdp_size,        verify_u16},
    {"udp.checksum",  kUdp_checksum,        verify_u16},
    { "udp.payload",   kUdp_payload,              NULL},
    {   "signature",     kSignature,     verify_string}
};

static const size_t SIGNATURE_FIELDS_SIZE = sizeof(SIGNATURE_FIELDS) / sizeof(SIGNATURE_FIELDS[0]);

pigsty_entry_ctx *load_pigsty_data_from_file(pigsty_entry_ctx *entry, const char *filepath) {
    char *data = get_pigsty_file_data(filepath);
    if (data != NULL) {
        if (!compile_pigsty_buffer(data)) {
            printf("pig panic: invalid signature detected, fix it and try again.\n");
            del_pigsty_entry(entry);
            free(data);
            return NULL;
        }
        free(data);
    } else {
        printf("pig panic: some i/o error happened.\n");
        del_pigsty_entry(entry);
        return NULL;
    }
    return entry;
}

static char *get_pigsty_file_data(const char *filepath) {
    char *retval = NULL;
    FILE *fp = fopen(filepath, "rb");
    long file_size = 0;
    if (fp == NULL) {
        printf("pig i/o panic: unable to open file \"%s\".\n", filepath);
        return NULL;
    }
    if (fseek(fp, 0L, SEEK_END) != -1) {
        file_size = ftell(fp);
        fseek(fp, 0L, SEEK_SET);
    } else {
        printf("pig i/o panic: unable to get some file informations from \"%s\".\n", filepath);
        fclose(fp);
        return NULL;
    }
    retval = (char *) pig_newseg(file_size + 1);
    memset(retval, 0, file_size + 1);
    if (fread(retval, 1, file_size, fp) == -1) {
        printf("pig i/o panic: unable to load data from file \"%s\".\n", filepath);
        free(retval);
        retval = NULL;
    }
    fclose(fp);
    return retval;
}

static char *skip_pigsty_comment(char *buffer) {
    char *b = buffer;
    while (*b != '\n' && *b != 0) {
        b++;
    }
    return b;
}

static char *skip_pigsty_blank(char *buffer) {
    char *b = buffer;
    while (is_pigsty_blank(*b)) {
        b++;
        if (is_pigsty_comment(*b)) b = skip_pigsty_comment(b);
    }
    return b;
}

static char *get_next_pigsty_word(char *buffer, char **next) {
    char *bp = buffer;
    char *end_bp = NULL;
    char *retval = NULL;
    bp = end_bp = skip_pigsty_blank(bp);
    while (!is_pigsty_blank(*end_bp) && *end_bp != 0) {
        if (*end_bp == '\"') {
            end_bp++;
            while (*end_bp != '\"' && *end_bp != 0) {
                end_bp++;
                if (*end_bp == '\\') {
                    end_bp += 2;
                }
            }
            end_bp++;
            break;
        } else {
            end_bp++;
            if (*end_bp == '=' || *end_bp == ',' || *end_bp == '>') {
    		break;
    	    }
        }        
    }
    *next = end_bp;
    retval = (char *) pig_newseg(end_bp - bp + 1);
    memset(retval, 0, end_bp - bp + 1);
    memcpy(retval, bp, end_bp - bp);
    return retval;
}

static int compile_next_buffered_pigsty_entry(char *buffer, char **next) {
    int all_ok = 1;
    char *token = get_next_pigsty_word(buffer, next);
    int state = 0;
    unsigned char field_map[SIGNATURE_FIELDS_SIZE];
    int field_index = 0;
    memset(field_map, 0, sizeof(field_map));
    if (*token != '<') {
        printf("pig panic: signature not well opened.\n");
        free(token);
        return 0;
    }
    free(token);
    buffer = *next;    
    token = get_next_pigsty_word(buffer, next);
    while (all_ok && **next != 0) {
	switch (state) {
            case 0:  //  field existence verifying
                field_index = get_pigsty_field_index(token);
                if (field_map[field_index] == 1) {
                    free(token);
                    printf("pig panic: field \"%s\" redeclared.\n", SIGNATURE_FIELDS[field_index].label);
                    return 0;
                }
                field_map[field_index] = 1;
                state = 1;
                break;
                
    	    case 1:
    		all_ok = (strcmp(token, "=") == 0);
    		if (!all_ok) {
    		    printf("pig panic: expecting \"=\" token.\n");
    		    free(token);
    		    return 0;
    		}
    		state = 2;
    		break;

            case 2:  //  field data verifying
        	if (SIGNATURE_FIELDS[field_index].verifier != NULL) {
                    all_ok = SIGNATURE_FIELDS[field_index].verifier(token);
	            if (!all_ok) {
    	        	printf("pig panic: field \"%s\" has invalid data (\"%s\").\n", SIGNATURE_FIELDS[field_index].label, token);
    	        	free(token);
                	return 0;
            	    }
            	}
            	state = 3;
                break;

            case 3:  //  next or end verifying
                all_ok = (*token == ',' || *token == '>');
                state = 0;
                if (!all_ok) {
                    printf("pig panic: missing \",\" or \">\".\n");
                    all_ok = 0;
                }
                break;
        }
        free(token);
        buffer = *next;
        token = get_next_pigsty_word(buffer, next);
    }
    return all_ok;
}

static int compile_pigsty_buffer(const char *buffer) {
    int all_ok = 1;
    char *data = (char *) buffer;
    char *next_data = NULL;
    all_ok = compile_next_buffered_pigsty_entry(data, &next_data);
    while (all_ok && *next_data != 0) {
        data = next_data;
        all_ok = compile_next_buffered_pigsty_entry(data, &next_data);
    }
    return all_ok;
}

static int verify_ip_version(const char *buffer) {
    return (strcmp(buffer, "4") == 0    || strcmp(buffer, "0x4") == 0 ||
            strcmp(buffer, "0x04") == 0 ||  strcmp(buffer, "04") == 0);
}

static int verify_string(const char *buffer) {
    return (buffer != NULL && (*buffer == '\"' && buffer[strlen(buffer) - 1] == '\"'));
}

static int verify_u1(const char *buffer) {
    int retval = 0;
    if (strlen(buffer) > 1 && *buffer == '0' && *(buffer + 1) == 'x') {
	retval = strtoul(buffer + 2, NULL, 16);
    } else {
	retval = atoi(buffer);
    }
    return (retval == 0x0 || retval == 0x1);
}

static int verify_u3(const char *buffer) {
    int retval = 0;
    if (strlen(buffer) > 1 && *buffer == '0' && *(buffer + 1) == 'x') {
	retval = strtoul(buffer + 2, NULL, 16);
    } else {
	retval = atoi(buffer);
    }
    return (retval >= 0x0 && retval <= 0x3);
}

static int verify_u4(const char *buffer) {
    int retval = 0;
    if (strlen(buffer) > 1 && *buffer == '0' && *(buffer + 1) == 'x') {
	retval = strtoul(buffer + 2, NULL, 16);
    } else {
	retval = atoi(buffer);
    }
    return (retval >= 0x0 && retval <= 0xf);
}

static int verify_u6(const char *buffer) {
    int retval = 0;
    if (strlen(buffer) > 1 && *buffer == '0' && *(buffer + 1) == 'x') {
	retval = strtoul(buffer + 2, NULL, 16);
    } else {
	retval = atoi(buffer);
    }
    return (retval >= 0x0 && retval <= 0x3f);
}

static int verify_u8(const char *buffer) {
    int retval = 0;
    if (strlen(buffer) > 1 && *buffer == '0' && *(buffer + 1) == 'x') {
	retval = strtoul(buffer + 2, NULL, 16);
    } else {
	retval = atoi(buffer);
    }
    return (retval >= 0x0 && retval <= 0xff);
}

static int verify_u13(const char *buffer) {
    int retval = 0;
    if (strlen(buffer) > 1 && *buffer == '0' && *(buffer + 1) == 'x') {
	retval = strtoul(buffer + 2, NULL, 16);
    } else {
	retval = atoi(buffer);
    }
    return (retval >= 0x0 && retval <= 0x1fff);
}

static int verify_u16(const char *buffer) {
    int retval = 0;
    if (strlen(buffer) > 1 && *buffer == '0' && *(buffer + 1) == 'x') {
	retval = strtoul(buffer + 2, NULL, 16);
    } else {
	retval = atoi(buffer);
    }
    return (retval >= 0x0 && retval <= 0xffff);
}

static int verify_u32(const char *buffer) {
    int retval = 0;
    if (strlen(buffer) > 1 && *buffer == '0' && *(buffer + 1) == 'x') {
	retval = strtoul(buffer + 2, NULL, 16);
    } else {
	retval = atoi(buffer);
    }
    return (retval >= 0x0 && retval <= 0xffffffff);
}

static int verify_ipv4_addr(const char *buffer) {
    int retval = 1;
    const char *b = buffer;
    int dots_nr = 0;
    char oct[255];
    size_t o = 0;
    memset(oct, 0, sizeof(oct));
    for (b = buffer; *b != 0 && retval; b++) {
	if (*b != '.' && !isdigit(*b)) {
	    return 0;
	}
	if (*b == '.' || *(b + 1) == 0) {
	    if (*(b + 1) == 0) {
		oct[o] = *b;
	    }
	    if (*b == '.') {
		dots_nr++;
	    }
	    retval = (atoi(oct) >= 0 && atoi(oct) <= 255);
	    o = -1;
	    memset(oct, 0, sizeof(oct));
	} else {
	    oct[o] = *b;
	}
	o = (o + 1) % sizeof(oct);
    }
    return (retval && dots_nr == 3);
}

static int get_pigsty_field_index(const char *field) {
    size_t f;
    for (f = 0; f < SIGNATURE_FIELDS_SIZE; f++) {
        if (strcmp(SIGNATURE_FIELDS[f].label, field) == 0) {
            return SIGNATURE_FIELDS[f].index;
        }
    }
    return -1;
}
