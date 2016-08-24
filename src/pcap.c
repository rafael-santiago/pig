/*
 *                                Copyright (C) 2016 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "pcap.h"
#include "memory.h"
#include <string.h>
#include <stdio.h>

#define new_pcap_record_ctx(p) ( (p) = (pcap_record_ctx *) pig_newseg(sizeof(pcap_record_ctx)),\
                                 (p)->next = NULL, (p)->data = NULL, memset(&(p)->hdr, 0, sizeof(pcap_record_header_t)) )


#define new_pcap_file_ctx(p) ( (p) = (pcap_file_ctx *) pig_newseg(sizeof(pcap_file_ctx)),\
                               (p)->path = NULL, (p)->rec = NULL, memset(&(p)->hdr, 0, sizeof(pcap_file_ctx)) )

static pcap_record_ctx *get_pcap_record_ctx_tail(pcap_record_ctx *recs);

static pcap_file_ctx *ld_records_from_pcap_file(pcap_file_ctx *file);

static pcap_file_ctx *get_pcap_file_global_info(const char *filepath);

static pcap_record_ctx *add_record_to_pcap_record_ctx(pcap_record_ctx *recs, pcap_record_header_t hdr, unsigned char *pkt_data);

static void del_pcap_file_ctx(pcap_file_ctx *file);

static void del_pcap_record_ctx(pcap_record_ctx *recs);

static void del_pcap_file_ctx(pcap_file_ctx *file) {
    if (file == NULL) {
        return;
    }
    free(file->path);
    del_pcap_record_ctx(file->rec);
}

pcap_file_ctx *ld_pcap_file(const char *filepath) {
    return ld_records_from_pcap_file(get_pcap_file_global_info(filepath));
}

void close_pcap_file(pcap_file_ctx *file) {
    del_pcap_file_ctx(file);
}

static pcap_file_ctx *get_pcap_file_global_info(const char *filepath) {
    FILE *fp = NULL;
    pcap_file_ctx *file = NULL;
    size_t pathsize = 0;
    if (filepath == NULL) {
        return NULL;
    }
    fp = fopen(filepath, "rb");
    if (fp == NULL) {
        return NULL;
    }
    new_pcap_file_ctx(file);
    pathsize = strlen(filepath);
    file->path = (char *) pig_newseg(pathsize + 1);
    memset(file->path, 0, pathsize + 1);
    strncpy(file->path, filepath, pathsize);
    fread(&file->hdr, 1, sizeof(file->hdr), fp);
    fclose(fp);
    return file;
}

static pcap_file_ctx *ld_records_from_pcap_file(pcap_file_ctx *file) {
    FILE *fp = NULL;
    pcap_record_header_t nrec;
    unsigned char ndata[65535];
    if (file == NULL || file->path == NULL) {
        return file;
    }
    fp = fopen(file->path, "rb");
    if (fp == NULL) {
        return file;
    }
    fseek(fp, sizeof(file->hdr), SEEK_SET);
    fread(&nrec, 1, sizeof(nrec), fp);
    fread(ndata, 1, nrec.incl_len, fp);
    while (!feof(fp)) {
        file->rec = add_record_to_pcap_record_ctx(file->rec, nrec, ndata);
        fread(&nrec, 1, sizeof(nrec), fp);
        fread(ndata, 1, nrec.incl_len, fp);
    }
    fclose(fp);
    return file;
}

static pcap_record_ctx *add_record_to_pcap_record_ctx(pcap_record_ctx *recs, pcap_record_header_t hdr, unsigned char *pkt_data) {
    pcap_record_ctx *head = recs, *p;
    if (pkt_data == NULL) {
        return head;
    }
    if (head == NULL) {
        new_pcap_record_ctx(head);
        p = head;
    } else {
        p = get_pcap_record_ctx_tail(head);
        new_pcap_record_ctx(p->next);
        p = p->next;
    }
    p->hdr = hdr;
    p->data = (unsigned char *) pig_newseg(p->hdr.incl_len + 1);
    memset(p->data, 0, p->hdr.incl_len + 1);
    memcpy(p->data, pkt_data, p->hdr.incl_len);
    return head;
}

static pcap_record_ctx *get_pcap_record_ctx_tail(pcap_record_ctx *recs) {
    pcap_record_ctx *r;
    for (r = recs; r->next != NULL; r = r->next);
    return r;
}

static void del_pcap_record_ctx(pcap_record_ctx *recs) {
    pcap_record_ctx *t, *p;
    for (t = p = recs; t; t = p->next, p = t) {
        free(p->data);
        free(p);
    }
}

int save_pcap_file(const pcap_file_ctx *file) {
    FILE *fp = NULL;
    pcap_record_ctx *rp = NULL;
    fp = fopen(file->path, "wb");
    if (fp == NULL) {
        return 0;
    }
    fwrite(&file->hdr, 1, sizeof(file->hdr), fp);
    for (rp = file->rec; rp != NULL; rp = rp->next) {
        fwrite(&rp->hdr, 1, sizeof(rp->hdr), fp);
        fwrite(rp->data, 1, rp->hdr.incl_len, fp);
    }
    fclose(fp);
    return 1;
}
