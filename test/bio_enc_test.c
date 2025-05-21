/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#define ENCRYPT  1
#define DECRYPT  0

static const unsigned char KEY[] = {
    0x51, 0x50, 0xd1, 0x77, 0x2f, 0x50, 0x83, 0x4a,
    0x50, 0x3e, 0x06, 0x9a, 0x97, 0x3f, 0xbd, 0x7c,
    0xe6, 0x1c, 0x43, 0x2b, 0x72, 0x0b, 0x19, 0xd1,
    0x8e, 0xc8, 0xd8, 0x4b, 0xdc, 0x63, 0x15, 0x1b
};

static const unsigned char IV[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

static int test_bio_enc_eof_read_flush(void)
{
    /* Length chosen to ensure base64 encoding employs padding */
    const unsigned char pbuf[] = "Attack at dawn";
    unsigned char cbuf[16];     /* At least as long as pbuf */
    const EVP_CIPHER *cipher = EVP_aes_256_gcm();
    EVP_CIPHER_CTX *ctx = NULL;
    BIO *mem = NULL, *b64 = NULL, *cbio = NULL;
    unsigned char tag[16];
    size_t key_size, iv_size;
    int n, ret = 0;

    memset(tag, 0, sizeof(tag));
    if (!(cipher)
        || !((key_size = EVP_CIPHER_key_length(cipher)) > 0)
        || !((iv_size = EVP_CIPHER_iv_length(cipher)) > 0)
        || !(mem = BIO_new(BIO_s_mem()))
        || !(b64 = BIO_new(BIO_f_base64()))
        || !(cbio = BIO_new(BIO_f_cipher()))
        || !(BIO_push(b64, mem))
        || !(BIO_push(cbio, b64))
        || !(BIO_get_cipher_ctx(cbio, &ctx) > 0)
        || !(EVP_CipherInit_ex(ctx, cipher, NULL, KEY, IV, ENCRYPT))
        || !(BIO_write(cbio, pbuf, sizeof(pbuf) - 1) > 0)
        || !(BIO_flush(cbio) > 0)
        || !(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                 sizeof(tag), tag) > 0))
        goto end;
    BIO_free(cbio);
    BIO_free(b64);
    b64 = cbio = NULL;

    BIO_set_mem_eof_return(mem, 0);
    BIO_set_flags(mem, BIO_FLAGS_NONCLEAR_RST);
    if (!(BIO_reset(mem) > 0)
        || !(b64 = BIO_new(BIO_f_base64()))
        || !(cbio = BIO_new(BIO_f_cipher()))
        || !(BIO_push(b64, mem))
        || !(BIO_push(cbio, b64))
        || !(BIO_get_cipher_ctx(cbio, &ctx) > 0)
        || !(EVP_CipherInit_ex(ctx, cipher, NULL, KEY, IV, DECRYPT))
        || !(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                 sizeof(tag), tag) > 0)
        || !((n = BIO_read(cbio, cbuf, sizeof(cbuf))) > 0)
        || !(BIO_get_cipher_status(cbio))
        /* Evaluate both and report whether either or both failed */
        || (!(BIO_flush(cbio) > 0) +
            !(BIO_get_cipher_status(cbio)))
        || n != sizeof(pbuf) - 1
        || memcmp(cbuf, pbuf, sizeof(pbuf) - 1))
        goto end;

    ret = 1;

 end:
    BIO_free(cbio);
    BIO_free(b64);
    BIO_free(mem);
    return ret;
}

int main()
{
    BIO *b;
    static const unsigned char key[16] = { 0 };
    static unsigned char inp[1024] = { 0 };
    unsigned char out[1024], ref[1024];
    int i, lref, len;

    /* Fill buffer with non-zero data so that over steps can be detected */
    if (RAND_bytes(inp, sizeof(inp)) <= 0)
        return -1;

    /*
     * Exercise CBC cipher
     */

    /* reference output for single-chunk operation */
    b = BIO_new(BIO_f_cipher());
    if (!BIO_set_cipher(b, EVP_aes_128_cbc(), key, NULL, 0))
        return -1;
    BIO_push(b, BIO_new_mem_buf(inp, sizeof(inp)));
    lref = BIO_read(b, ref, sizeof(ref));
    BIO_free_all(b);

    /* perform split operations and compare to reference */
    for (i = 1; i < lref; i++) {
        b = BIO_new(BIO_f_cipher());
        if (!BIO_set_cipher(b, EVP_aes_128_cbc(), key, NULL, 0))
             return -1;
        BIO_push(b, BIO_new_mem_buf(inp, sizeof(inp)));
        memset(out, 0, sizeof(out));
        out[i] = ~ref[i];
        len = BIO_read(b, out, i);
        /* check for overstep */
        if (out[i] != (unsigned char)~ref[i]) {
            fprintf(stderr, "CBC output overstep@%d\n", i);
            return 1;
        }
        len += BIO_read(b, out + len, sizeof(out) - len);
        BIO_free_all(b);

        if (len != lref || memcmp(out, ref, len)) {
            fprintf(stderr, "CBC output mismatch@%d\n", i);
            return 2;
        }
    }

    /* perform small-chunk operations and compare to reference */
    for (i = 1; i < lref / 2; i++) {
        int delta;

        b = BIO_new(BIO_f_cipher());
        if (!BIO_set_cipher(b, EVP_aes_128_cbc(), key, NULL, 0))
             return -1;
        BIO_push(b, BIO_new_mem_buf(inp, sizeof(inp)));
        memset(out, 0, sizeof(out));
        for (len = 0; (delta = BIO_read(b, out + len, i)); ) {
            len += delta;
        }
        BIO_free_all(b);

        if (len != lref || memcmp(out, ref, len)) {
            fprintf(stderr, "CBC output mismatch@%d\n", i);
            return 3;
        }
    }

    /*
     * Exercise CTR cipher
     */

    /* reference output for single-chunk operation */
    b = BIO_new(BIO_f_cipher());
    if (!BIO_set_cipher(b, EVP_aes_128_ctr(), key, NULL, 0))
         return -1;
    BIO_push(b, BIO_new_mem_buf(inp, sizeof(inp)));
    lref = BIO_read(b, ref, sizeof(ref));
    BIO_free_all(b);

    /* perform split operations and compare to reference */
    for (i = 1; i < lref; i++) {
        b = BIO_new(BIO_f_cipher());
        if (!BIO_set_cipher(b, EVP_aes_128_ctr(), key, NULL, 0))
             return -1;
        BIO_push(b, BIO_new_mem_buf(inp, sizeof(inp)));
        memset(out, 0, sizeof(out));
        out[i] = ~ref[i];
        len = BIO_read(b, out, i);
        /* check for overstep */
        if (out[i] != (unsigned char)~ref[i]) {
            fprintf(stderr, "CTR output overstep@%d\n", i);
            return 4;
        }
        len += BIO_read(b, out + len, sizeof(out) - len);
        BIO_free_all(b);

        if (len != lref || memcmp(out, ref, len)) {
            fprintf(stderr, "CTR output mismatch@%d\n", i);
            return 5;
        }
    }

    /* perform small-chunk operations and compare to reference */
    for (i = 1; i < lref / 2; i++) {
        int delta;

        b = BIO_new(BIO_f_cipher());
        if (!BIO_set_cipher(b, EVP_aes_128_ctr(), key, NULL, 0))
             return -1;
        BIO_push(b, BIO_new_mem_buf(inp, sizeof(inp)));
        memset(out, 0, sizeof(out));
        for (len = 0; (delta = BIO_read(b, out + len, i)); ) {
            len += delta;
        }
        BIO_free_all(b);

        if (len != lref || memcmp(out, ref, len)) {
            fprintf(stderr, "CTR output mismatch@%d\n", i);
            return 6;
        }
    }

    return test_bio_enc_eof_read_flush() ? 0 : 7;
}
