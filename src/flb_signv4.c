/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *
 * AWS Signv4 documentation
 *
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_http_client.h>
#include <mbedtls/sha256.h>

#include <stdlib.h>
#include <ctype.h>

static int kv_key_cmp(const void *a_arg, const void *b_arg)
{
    struct flb_kv *kv_a = *(struct flb_kv **) a_arg;
    struct flb_kv *kv_b = *(struct flb_kv **) b_arg;

    return strcmp(kv_a->key, kv_b->key);
}

static inline int to_encode(char c)
{
    if ((c >= 48 && c <= 57)  ||  /* 0-9 */
        (c >= 65 && c <= 90)  ||  /* A-Z */
        (c >= 97 && c <= 122) ||  /* a-z */
        (c == '-' || c == '_' || c == '.' || c == '~')) {
        return FLB_FALSE;
    }

    return FLB_TRUE;
}

static flb_sds_t uri_encode(const char *uri, size_t len)
{
    int i;
    flb_sds_t buf = NULL;
    flb_sds_t tmp = NULL;

    buf = flb_sds_create_size(len * 2);
    if (!buf) {
        flb_error("[signv4] cannot allocate buffer for URI encoding");
        return NULL;
    }

    for (i = 0; i < len; i++) {
        if (to_encode(uri[i]) == FLB_TRUE) {
            tmp = flb_sds_printf(&buf, "%%X", *(uri + i));
            if (!tmp) {
                flb_error("[signv4] error formatting special character");
                flb_sds_destroy(buf);
                return NULL;
            }
            buf = tmp;
            continue;
        }

        /* Direct assignment, just copy the character */
        if (buf) {
            tmp = flb_sds_cat(buf, uri + i, 1);
            if (!tmp) {
                flb_error("[signv4] error composing outgoing buffer");
                flb_sds_destroy(buf);
                return NULL;
            }
        }
    }

    return buf;
}

/* Convert a query string to a sorted key/value linked list */
static flb_sds_t query_string_format(char *qs)
{
    int i;
    int ret;
    int len;
    int items;
    char *p;
    struct mk_list list;
    struct mk_list split;
    struct mk_list *h_tmp;
    struct mk_list *head;
    struct flb_slist_entry *e;
    flb_sds_t key;
    flb_sds_t val;
    flb_sds_t tmp;
    flb_sds_t buf = NULL;
    struct flb_kv *kv;
    struct flb_kv **arr;

    mk_list_init(&list);
    mk_list_init(&split);

    ret = flb_slist_split_string(&split, qs, '&', -1);
    if (ret == -1) {
        flb_error("[signv4] error processing given query string");
        return NULL;
    }

    mk_list_foreach_safe(head, h_tmp, &split) {
        e = mk_list_entry(head, struct flb_slist_entry, _head);
        p = strchr(e->str, '=');
        if (!p) {
            continue;
        }

        len = (p - e->str);
        p++;
        len++;

        /* URI encode every key and value */
        key = uri_encode(e->str, len);
        val = uri_encode(p, flb_sds_len(e->str) - len);
        if (!key || !val) {
            flb_error("[signv4] error encoding uri for query string");
            flb_slist_destroy(&split);
            flb_kv_release(&list);
            return NULL;
        }

        kv = flb_kv_item_create_len(&list,
                                    key, flb_sds_len(key),
                                    val, flb_sds_len(val));
        flb_sds_destroy(key);
        flb_sds_destroy(val);

        if (!kv) {
            flb_error("[signv4] error processing key/value from query string");
            flb_slist_destroy(&split);
            flb_kv_release(&list);
            return NULL;
        }

        /* Check converted values */
        printf("> query string: key='%s' val='%s'\n", kv->key, kv->val);
    }
    flb_slist_destroy(&split);

    /* Sort the kv list of parameters */
    items = mk_list_size(&list);
    if (items == 0) {
        return flb_sds_create("");
    }

    arr = flb_malloc(sizeof(struct flb_kv *) * items);
    if (!arr) {
        flb_errno();
        flb_kv_release(&list);
        return NULL;
    }

    i = 0;
    mk_list_foreach(head, &list) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        arr[i] = kv;
    }
    qsort(arr, items, sizeof(struct flb_kv *), kv_key_cmp);


    /* Format query string parameters */
    buf = flb_sds_create_size(items * 64);
    if (!buf) {
        flb_kv_release(&list);
        flb_free(arr);
        return NULL;
    }

    for (i = 0; i < items; i++) {
        kv = (struct flb_kv *) arr[i];
        if (i + 1 < items) {
            tmp = flb_sds_printf(&buf, "%s=%s&\n",
                                 kv->key, kv->val);
        }
        else {
            tmp = flb_sds_printf(&buf, "%s=%s\n",
                                 kv->key, kv->val);
        }
        buf = tmp;
    }

    return buf;
}

/*
 * Create a canonical request:
 *
 *  CanonicalRequest =
 *  HTTPRequestMethod + '\n' +
 *  CanonicalURI + '\n' +
 *  CanonicalQueryString + '\n' +
 *  CanonicalHeaders + '\n' +
 *  SignedHeaders + '\n' +
 *  HexEncode(Hash(RequestPayload))
 */
int flb_signv4_canonical_request(struct flb_http_client *c)
{
    int i;
    int x;
    int len;
    int items;
    size_t size;
    struct flb_kv **arr;
    char buf[32];
    flb_sds_t cr;
    flb_sds_t uri;
    flb_sds_t tmp = NULL;
    struct flb_kv *kv;
    struct flb_kv *kv_host;
    struct flb_kv *kv_content_len;
    struct mk_list qs_list;
    struct mk_list list_tmp;
    struct mk_list *head;
    unsigned char sha256_buf[64] = {0};
    mbedtls_sha256_context sha256_ctx;

    /* Size hint */
    size = strlen(c->uri) + (mk_list_size(&c->headers) * 64) + 256;

    cr = flb_sds_create_size(size);
    if (!cr) {
        flb_error("[signv4] cannot allocate buffer");
        return -1;
    }

    switch (c->method) {
    case FLB_HTTP_GET:
        tmp = flb_sds_cat(cr, "GET\n", 4);
        break;
    case FLB_HTTP_POST:
        tmp = flb_sds_cat(cr, "POST\n", 5);
        break;
    case FLB_HTTP_PUT:
        tmp = flb_sds_cat(cr, "PUT\n", 4);
        break;
    case FLB_HTTP_HEAD:
        tmp = flb_sds_cat(cr, "HEAD\n", 5);
        break;
    };

    if (!tmp) {
        flb_error("[signv4] invalid processing of HTTP method");
        flb_sds_destroy(cr);
        return -1;
    }

    cr = tmp;

    /* Our URI already contains the query string, so do the proper adjustments */
    if (c->query_string) {
        len = (c->query_string - c->uri);
    }
    else {
        len = strlen(c->uri);
    }

    /* Do URI encoding (rfc3986) */
    uri = uri_encode(c->uri, len);
    if (!uri) {
        /* error composing outgoing buffer */
        flb_sds_destroy(cr);
        return -1;
    }

    tmp = flb_sds_cat(cr, uri, flb_sds_len(uri));
    if (!tmp) {
        flb_error("[signv4] error concatenating encoded URI");
        flb_sds_destroy(uri);
        flb_sds_destroy(cr);
        return -1;
    }
    cr = tmp;
    flb_sds_destroy(uri);

    tmp = flb_sds_cat(cr, "\n", 1);
    if (!tmp) {
        flb_error("[signv4] error concatenating encoded URI break line");
        flb_sds_destroy(cr);
        return -1;
    }
    cr = tmp;

    /* Canonical Query String */
    if (c->query_string == NULL) {
        tmp = flb_sds_cat(cr, "\n", 1);
    }
    else {
        mk_list_init(&qs_list);
        tmp = query_string_format((char *) c->query_string);
        if (!tmp) {
            flb_sds_destroy(cr);
            return -1;
        }
        tmp = flb_sds_cat(cr, tmp, flb_sds_len(tmp));
    }
    if (!tmp) {
        flb_error("[signv4] error concatenating query string");
        flb_sds_destroy(cr);
        return -1;
    }
    cr = tmp;

    /*
     * Canonical Headers
     *
     * Append to temporal list two fixed headers used for the signature
     *
     * - host
     * - content_length
     */
    len = strlen(c->host);
    mk_list_init(&list_tmp);
    kv_host = flb_kv_item_create_len(&list_tmp, "host", 4, (char *) c->host, len);

    len = snprintf(buf, sizeof(buf) - 1, "%i", c->body_len);
    kv_content_len = flb_kv_item_create_len(&list_tmp,
                                            "content-length", 14, buf, len);

    /*
     * For every header registered, append it to the temporal array so we can sort them
     * later.
     */
    items = mk_list_size(&c->headers) + 2;
    size = (sizeof(struct flb_kv *) * items);
    arr = flb_malloc(size);
    if (!arr) {
        flb_errno();
        flb_kv_release(&list_tmp);
        flb_sds_destroy(cr);
        return -1;
    }
    arr[0] = (struct flb_kv *) kv_host;
    arr[1] = kv_content_len;

    i = 2;
    mk_list_foreach(head, &c->headers) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        /*
         * The original headers might have upper case characters, for safety just
         * make a copy of them so we can lowercase them if required.
         */
        kv = flb_kv_item_create_len(&list_tmp,
                                    kv->key, flb_sds_len(kv->key),
                                    kv->val, flb_sds_len(kv->val));
        for (x = 0; x < flb_sds_len(kv->key); x++) {
            kv->key[x] = tolower(kv->key[x]);
        }
        arr[i] = kv;
        i++;
    }

    /* Sort the headers from the temporal array */
    qsort(arr, items, sizeof(struct flb_kv *), kv_key_cmp);

    /* Iterate sorted headers and appendn them to the outgoing buffer */
    mk_list_foreach(head, &list_tmp) {
        kv = mk_list_entry(head, struct flb_kv, _head);
        tmp = flb_sds_printf(&cr, "%s:%s\n", kv->key, kv->val);
        if (!tmp) {
            flb_error("[signv4] error composing canonical headers");
            flb_kv_release(&list_tmp);
            flb_sds_destroy(cr);
            return -1;
        }
        cr = tmp;
    }

    /* Canonical Signed Headers */
    mk_list_foreach(head, &list_tmp) {
        kv = mk_list_entry(head, struct flb_kv, _head);

        /* Check if this is the last header, if so add breakline separator */
        if (head == list_tmp.prev) {
            tmp = flb_sds_printf(&cr, "%s\n", kv->key);
        }
        else {
            tmp = flb_sds_printf(&cr, "%s;", kv->key);
        }
        if (!tmp) {
            flb_error("[signv4] error composing canonical signed headers");
            flb_kv_release(&list_tmp);
            flb_sds_destroy(cr);
            return -1;
        }
        cr = tmp;
    }
    flb_kv_release(&list_tmp);

    /* Hashed Payload */
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    if (c->body_len > 0) {
        mbedtls_sha256_update(&sha256_ctx, (const unsigned char *) c->body_buf,
                              c->body_len);
    }
    mbedtls_sha256_finish(&sha256_ctx, sha256_buf);

    for (i = 0; i < 64; i++) {
        tmp = flb_sds_printf(&cr, "%02x", sha256_buf[i]);
        if (!tmp) {
            flb_error("[signedv4] error formatting hashed payload");
            flb_sds_destroy(cr);
            return -1;
        }
        cr = tmp;
    }
    return 0;
}
