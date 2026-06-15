/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <limits.h>
#include "internal/cryptlib.h"
#include "internal/numbers.h"
#include <openssl/buffer.h>
#include <openssl/asn1.h>

static int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb);

#ifndef NO_OLD_ASN1
# ifndef OPENSSL_NO_STDIO

void *ASN1_d2i_fp(void *(*xnew) (void), d2i_of_void *d2i, FILE *in, void **x)
{
    BIO *b;
    void *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ASN1err(ASN1_F_ASN1_D2I_FP, ERR_R_BUF_LIB);
        return (NULL);
    }
    BIO_set_fp(b, in, BIO_NOCLOSE);
    ret = ASN1_d2i_bio(xnew, d2i, b, x);
    BIO_free(b);
    return (ret);
}
# endif

void *ASN1_d2i_bio(void *(*xnew) (void), d2i_of_void *d2i, BIO *in, void **x)
{
    BUF_MEM *b = NULL;
    const unsigned char *p;
    void *ret = NULL;
    int len;

    len = asn1_d2i_read_bio(in, &b);
    if (len < 0)
        goto err;

    p = (unsigned char *)b->data;
    ret = d2i(x, &p, len);
 err:
    BUF_MEM_free(b);
    return (ret);
}

#endif

void *ASN1_item_d2i_bio(const ASN1_ITEM *it, BIO *in, void *x)
{
    BUF_MEM *b = NULL;
    const unsigned char *p;
    void *ret = NULL;
    int len;

    len = asn1_d2i_read_bio(in, &b);
    if (len < 0)
        goto err;

    p = (const unsigned char *)b->data;
    ret = ASN1_item_d2i(x, &p, len, it);
 err:
    BUF_MEM_free(b);
    return (ret);
}

#ifndef OPENSSL_NO_STDIO
void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x)
{
    BIO *b;
    char *ret;

    if ((b = BIO_new(BIO_s_file())) == NULL) {
        ASN1err(ASN1_F_ASN1_ITEM_D2I_FP, ERR_R_BUF_LIB);
        return (NULL);
    }
    BIO_set_fp(b, in, BIO_NOCLOSE);
    ret = ASN1_item_d2i_bio(it, b, x);
    BIO_free(b);
    return (ret);
}
#endif

#define HEADER_SIZE   2
#define ASN1_CHUNK_INITIAL_SIZE (16 * 1024)
static int asn1_d2i_read_bio(BIO *in, BUF_MEM **pb)
{
    BUF_MEM *b;
    unsigned char *p;
    int i;
    size_t want = HEADER_SIZE;
    uint32_t eos = 0;
    size_t off = 0;
    size_t len = 0;
    size_t diff;

    const unsigned char *q;
    long slen;
    int inf, tag, xclass;

    b = BUF_MEM_new();
    if (b == NULL) {
        ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ERR_R_MALLOC_FAILURE);
        return -1;
    }

    ERR_clear_error();
    for (;;) {
        diff = len - off;
        if (want >= diff) {
            want -= diff;

            if (len + want < len || !BUF_MEM_grow_clean(b, len + want)) {
                ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ERR_R_MALLOC_FAILURE);
                goto err;
            }
            i = BIO_read(in, &(b->data[len]), want);
            if (i <= 0) {
                /*
                 * A read error (i < 0), an EOF in the middle of an object
                 * (diff != 0, some bytes already buffered), or an EOF while
                 * still inside an indefinite-length constructed value awaiting
                 * its end-of-contents octets (eos != 0) all mean the input is
                 * truncated.  Only a clean EOF at a top-level object boundary
                 * (i == 0, diff == 0, eos == 0) is the normal end of input:
                 * fail without queuing an error so that callers looping over
                 * concatenated DER values (e.g. the libcrypto d2i_*_bio()
                 * consumers in CPython's ssl module) terminate cleanly instead
                 * of seeing a spurious ASN1_R_NOT_ENOUGH_DATA.
                 */
                if (i < 0 || diff != 0 || eos != 0)
                    ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_NOT_ENOUGH_DATA);
                goto err;
            }
            if (i > 0) {
                if (len + i < len) {
                    ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_TOO_LONG);
                    goto err;
                }
                len += i;
                want += diff;
                if (len - off < want)
                    continue;
            }
        }
        /* else data already loaded */

        /* make sure there is enough data for a complete header */
        p = (unsigned char *)&(b->data[off]);
        q = p;
        diff = len - off;
        if (diff < 2) {
            /* Failed sanity check */
            ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_NOT_ENOUGH_DATA);
            goto err;
        }

        diff--;
        if ((*(q++) & V_ASN1_PRIMITIVE_TAG) == V_ASN1_PRIMITIVE_TAG) {
            unsigned int n = 0;
            /* Multi-byte tag.  See if we have the whole thing yet */
            do {
                if (n > 5) {
                    /* The tag value must fit into int */
                    ASN1err(ASN1_F_ASN1_D2I_READ_BIO,
                            ASN1_R_HEADER_TOO_LONG);
                    goto err;
                }
                ++n;
                diff--;
            } while (diff > 0 && *(q++) & 0x80);

            if (diff == 0) {
                /*
                 * End of current data, will need at least 1 more byte for
                 * length.  2 if the tag is still incomplete
                 */
                want = q - p + 2;
                if (*q & 0x80) {
                    want++;
                }
                continue;
            }
        }

        /* Check the length.  This should also work for indefinite length */
        diff--;
        if (*q & 0x80) {
            unsigned int n = *q & 0x7f;

            /*
             * Tolerate BER length encoding which may include leading zeroes,
             * since ASN1_get_object does also accept BER encoding.
             */
            if (n > diff) {
                want = q - p + n + 1;
                continue;
            }
        }

        /*
         * We have a complete header now, assuming we didn't hit EOF. Parse the
         * tag and length
         */
        q = p;
        diff = len - off;
        inf = ASN1_get_object(&q, &slen, &tag, &xclass, (int)diff);
        if (inf & 0x80) {
            unsigned long e;

            e = ERR_GET_REASON(ERR_peek_error());
            if (e != ASN1_R_TOO_LONG)
                goto err;
            else
                ERR_clear_error(); /* clear error */
        }
        off += q - p; /* end of data */

        if (inf & 1) {
            /* no data body so go round again */
            if (eos == UINT32_MAX) {
                ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_HEADER_TOO_LONG);
                goto err;
            }
            eos++;
            want = HEADER_SIZE;
        } else if (eos && (slen == 0) && (tag == V_ASN1_EOC)) {
            /* eos value, so go back and read another header */
            eos--;
            if (eos == 0)
                break;
            else
                want = HEADER_SIZE;
        } else {
            /* suck in slen bytes of data */
            want = slen;
            if (want > (len - off)) {
                size_t chunk_max = ASN1_CHUNK_INITIAL_SIZE;

                want -= (len - off);
                if (want > INT_MAX /* BIO_read takes an int length */  ||
                    len + want < len) {
                    ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_TOO_LONG);
                    goto err;
                }
                while (want > 0) {
                    /*
                     * Read content in chunks of increasing size
                     * so we can return an error for EOF without
                     * having to allocate the entire content length
                     * in one go.
                     */
                    size_t chunk = want > chunk_max ? chunk_max : want;

                    if (!BUF_MEM_grow_clean(b, len + chunk)) {
                        ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ERR_R_MALLOC_FAILURE);
                        goto err;
                    }
                    want -= chunk;
                    while (chunk > 0) {
                        i = BIO_read(in, &(b->data[len]), chunk);
                        if (i <= 0) {
                            ASN1err(ASN1_F_ASN1_D2I_READ_BIO,
                                    ASN1_R_NOT_ENOUGH_DATA);
                            goto err;
                        }
                    /*
                     * This can't overflow because |len+want| didn't
                     * overflow.
                     */
                        len += i;
                        chunk -= i;
                    }
                    if (chunk_max < INT_MAX/2)
                        chunk_max *= 2;
                }
            }
            if (off + slen < off) {
                ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_TOO_LONG);
                goto err;
            }
            off += slen;
            if (eos == 0) {
                break;
            } else
                want = HEADER_SIZE;
        }
    }

    if (off > INT_MAX) {
        ASN1err(ASN1_F_ASN1_D2I_READ_BIO, ASN1_R_TOO_LONG);
        goto err;
    }

    *pb = b;
    return off;
 err:
    BUF_MEM_free(b);
    return -1;
}
