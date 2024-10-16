/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/dsa.h>

#include "testutil.h"
#include "internal/nelem.h"

#ifndef OPENSSL_NO_DSA
static int dsa_cb(int p, int n, BN_GENCB *arg);

static unsigned char out_p[] = {
    0x8d, 0xf2, 0xa4, 0x94, 0x49, 0x22, 0x76, 0xaa,
    0x3d, 0x25, 0x75, 0x9b, 0xb0, 0x68, 0x69, 0xcb,
    0xea, 0xc0, 0xd8, 0x3a, 0xfb, 0x8d, 0x0c, 0xf7,
    0xcb, 0xb8, 0x32, 0x4f, 0x0d, 0x78, 0x82, 0xe5,
    0xd0, 0x76, 0x2f, 0xc5, 0xb7, 0x21, 0x0e, 0xaf,
    0xc2, 0xe9, 0xad, 0xac, 0x32, 0xab, 0x7a, 0xac,
    0x49, 0x69, 0x3d, 0xfb, 0xf8, 0x37, 0x24, 0xc2,
    0xec, 0x07, 0x36, 0xee, 0x31, 0xc8, 0x02, 0x91,
};
static unsigned char out_q[] = {
    0xc7, 0x73, 0x21, 0x8c, 0x73, 0x7e, 0xc8, 0xee,
    0x99, 0x3b, 0x4f, 0x2d, 0xed, 0x30, 0xf4, 0x8e,
    0xda, 0xce, 0x91, 0x5f,
};
static unsigned char out_g[] = {
    0x62, 0x6d, 0x02, 0x78, 0x39, 0xea, 0x0a, 0x13,
    0x41, 0x31, 0x63, 0xa5, 0x5b, 0x4c, 0xb5, 0x00,
    0x29, 0x9d, 0x55, 0x22, 0x95, 0x6c, 0xef, 0xcb,
    0x3b, 0xff, 0x10, 0xf3, 0x99, 0xce, 0x2c, 0x2e,
    0x71, 0xcb, 0x9d, 0xe5, 0xfa, 0x24, 0xba, 0xbf,
    0x58, 0xe5, 0xb7, 0x95, 0x21, 0x92, 0x5c, 0x9c,
    0xc4, 0x2e, 0x9f, 0x6f, 0x46, 0x4b, 0x08, 0x8c,
    0xc5, 0x72, 0xaf, 0x53, 0xe6, 0xd7, 0x88, 0x02,
};

static int dsa_test(void)
{
    BN_GENCB *cb;
    DSA *dsa = NULL;
    int counter, ret = 0, i, j;
    unsigned char buf[256];
    unsigned long h;
    unsigned char sig[256];
    unsigned int siglen;
    const BIGNUM *p = NULL, *q = NULL, *g = NULL;
    /*
     * seed, out_p, out_q, out_g are taken from the updated Appendix 5 to FIPS
     * PUB 186 and also appear in Appendix 5 to FIPS PIB 186-1
     */
    static unsigned char seed[20] = {
        0xd5, 0x01, 0x4e, 0x4b, 0x60, 0xef, 0x2b, 0xa8,
        0xb6, 0x21, 0x1b, 0x40, 0x62, 0xba, 0x32, 0x24,
        0xe0, 0x42, 0x7d, 0xd3,
    };
    static const unsigned char str1[] = "12345678901234567890";

    if (!TEST_ptr(cb = BN_GENCB_new()))
        goto end;

    BN_GENCB_set(cb, dsa_cb, NULL);
    if (!TEST_ptr(dsa = DSA_new())
        || !TEST_true(DSA_generate_parameters_ex(dsa, 512, seed, 20,
                                                &counter, &h, cb)))
        goto end;

    if (!TEST_int_eq(counter, 105))
        goto end;
    if (!TEST_int_eq(h, 2))
        goto end;

    DSA_get0_pqg(dsa, &p, &q, &g);
    i = BN_bn2bin(q, buf);
    j = sizeof(out_q);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_q, i))
        goto end;

    i = BN_bn2bin(p, buf);
    j = sizeof(out_p);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_p, i))
        goto end;

    i = BN_bn2bin(g, buf);
    j = sizeof(out_g);
    if (!TEST_int_eq(i, j) || !TEST_mem_eq(buf, i, out_g, i))
        goto end;

    DSA_generate_key(dsa);
    DSA_sign(0, str1, 20, sig, &siglen, dsa);
    if (TEST_true(DSA_verify(0, str1, 20, sig, siglen, dsa)))
        ret = 1;
 end:
    DSA_free(dsa);
    BN_GENCB_free(cb);
    return ret;
}

static int dsa_cb(int p, int n, BN_GENCB *arg)
{
    static int ok = 0, num = 0;

    if (p == 0)
        num++;
    if (p == 2)
        ok++;

    if (!ok && (p == 0) && (num > 1)) {
        TEST_error("dsa_cb error");
        return 0;
    }
    return 1;
}

static int test_dsa_sig_infinite_loop(void)
{
    int ret = 0;
    DSA *dsa = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *pub = NULL, *priv2 = NULL;
    BIGNUM *badq = NULL, *badpriv = NULL;
    const unsigned char msg[] = { 0x00 };
    unsigned int signature_len0;
    unsigned int signature_len;
    unsigned char signature[64];

    static unsigned char out_priv[] = {
        0x17, 0x00, 0xb2, 0x8d, 0xcb, 0x24, 0xc9, 0x98,
        0xd0, 0x7f, 0x1f, 0x83, 0x1a, 0xa1, 0xc4, 0xa4,
        0xf8, 0x0f, 0x7f, 0x12
    };
    static unsigned char out_pub[] = {
        0x04, 0x72, 0xee, 0x8d, 0xaa, 0x4d, 0x89, 0x60,
        0x0e, 0xb2, 0xd4, 0x38, 0x84, 0xa2, 0x2a, 0x60,
        0x5f, 0x67, 0xd7, 0x9e, 0x24, 0xdd, 0xe8, 0x50,
        0xf2, 0x23, 0x71, 0x55, 0x53, 0x94, 0x0d, 0x6b,
        0x2e, 0xcd, 0x30, 0xda, 0x6f, 0x1e, 0x2c, 0xcf,
        0x59, 0xbe, 0x05, 0x6c, 0x07, 0x0e, 0xc6, 0x38,
        0x05, 0xcb, 0x0c, 0x44, 0x0a, 0x08, 0x13, 0xb6,
        0x0f, 0x14, 0xde, 0x4a, 0xf6, 0xed, 0x4e, 0xc3
    };
    if (!TEST_ptr(p = BN_bin2bn(out_p, sizeof(out_p), NULL))
        || !TEST_ptr(q = BN_bin2bn(out_q, sizeof(out_q), NULL))
        || !TEST_ptr(g = BN_bin2bn(out_g, sizeof(out_g), NULL))
        || !TEST_ptr(pub = BN_bin2bn(out_pub, sizeof(out_pub), NULL))
        || !TEST_ptr(priv = BN_bin2bn(out_priv, sizeof(out_priv), NULL))
        || !TEST_ptr(priv2 = BN_dup(priv))
        || !TEST_ptr(badq = BN_new())
        || !TEST_true(BN_set_word(badq, 1))
        || !TEST_ptr(badpriv = BN_new())
        || !TEST_true(BN_set_word(badpriv, 0))
        || !TEST_ptr(dsa = DSA_new()))
        goto err;

    if (!TEST_true(DSA_set0_pqg(dsa, p, q, g)))
        goto err;
    p = q = g = NULL;

    if (!TEST_true(DSA_set0_key(dsa, pub, priv)))
        goto err;
    pub = priv = NULL;

    if (!TEST_int_le(DSA_size(dsa), sizeof(signature)))
        goto err;

    /* Test passing signature as NULL */
    if (!TEST_true(DSA_sign(0, msg, sizeof(msg), NULL, &signature_len0, dsa))
        || !TEST_int_gt(signature_len0, 0))
        goto err;

    if (!TEST_true(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa))
        || !TEST_int_gt(signature_len, 0)
        || !TEST_int_le(signature_len, signature_len0))
        goto err;

    /* Test using a private key of zero fails - this causes an infinite loop without the retry test */
    if (!TEST_true(DSA_set0_key(dsa, NULL, badpriv)))
        goto err;
    badpriv = NULL;
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    /* Restore private and set a bad q - this caused an infinite loop in the setup */
    if (!TEST_true(DSA_set0_key(dsa, NULL, priv2)))
        goto err;
    priv2 = NULL;
    if (!TEST_true(DSA_set0_pqg(dsa, NULL, badq, NULL)))
        goto err;
    badq = NULL;
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(badq);
    BN_free(badpriv);
    BN_free(pub);
    BN_free(priv);
    BN_free(priv2);
    BN_free(g);
    BN_free(q);
    BN_free(p);
    DSA_free(dsa);
    return ret;
}

static int test_dsa_sig_neg_param(void)
{
    int ret = 0, setpqg = 0;
    DSA *dsa = NULL;
    BIGNUM *p = NULL, *q = NULL, *g = NULL, *priv = NULL, *pub = NULL;
    const unsigned char msg[] = { 0x00 };
    unsigned int signature_len;
    unsigned char signature[64];

    static unsigned char out_priv[] = {
        0x17, 0x00, 0xb2, 0x8d, 0xcb, 0x24, 0xc9, 0x98,
        0xd0, 0x7f, 0x1f, 0x83, 0x1a, 0xa1, 0xc4, 0xa4,
        0xf8, 0x0f, 0x7f, 0x12
    };
    static unsigned char out_pub[] = {
        0x04, 0x72, 0xee, 0x8d, 0xaa, 0x4d, 0x89, 0x60,
        0x0e, 0xb2, 0xd4, 0x38, 0x84, 0xa2, 0x2a, 0x60,
        0x5f, 0x67, 0xd7, 0x9e, 0x24, 0xdd, 0xe8, 0x50,
        0xf2, 0x23, 0x71, 0x55, 0x53, 0x94, 0x0d, 0x6b,
        0x2e, 0xcd, 0x30, 0xda, 0x6f, 0x1e, 0x2c, 0xcf,
        0x59, 0xbe, 0x05, 0x6c, 0x07, 0x0e, 0xc6, 0x38,
        0x05, 0xcb, 0x0c, 0x44, 0x0a, 0x08, 0x13, 0xb6,
        0x0f, 0x14, 0xde, 0x4a, 0xf6, 0xed, 0x4e, 0xc3
    };
    if (!TEST_ptr(p = BN_bin2bn(out_p, sizeof(out_p), NULL))
        || !TEST_ptr(q = BN_bin2bn(out_q, sizeof(out_q), NULL))
        || !TEST_ptr(g = BN_bin2bn(out_g, sizeof(out_g), NULL))
        || !TEST_ptr(pub = BN_bin2bn(out_pub, sizeof(out_pub), NULL))
        || !TEST_ptr(priv = BN_bin2bn(out_priv, sizeof(out_priv), NULL))
        || !TEST_ptr(dsa = DSA_new()))
        goto err;

    if (!TEST_true(DSA_set0_pqg(dsa, p, q, g)))
        goto err;
    setpqg = 1;

    if (!TEST_true(DSA_set0_key(dsa, pub, priv)))
        goto err;
    pub = priv = NULL;

    BN_set_negative(p, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 0);
    BN_set_negative(q, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(q, 0);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    BN_set_negative(p, 1);
    BN_set_negative(q, 1);
    BN_set_negative(g, 1);
    if (!TEST_false(DSA_sign(0, msg, sizeof(msg), signature, &signature_len, dsa)))
        goto err;

    ret = 1;
err:
    BN_free(pub);
    BN_free(priv);

    if (setpqg == 0) {
        BN_free(g);
        BN_free(q);
        BN_free(p);
    }
    DSA_free(dsa);
    return ret;
}

#endif /* OPENSSL_NO_DSA */

int setup_tests(void)
{
#ifndef OPENSSL_NO_DSA
    ADD_TEST(dsa_test);
    ADD_TEST(test_dsa_sig_infinite_loop);
    ADD_TEST(test_dsa_sig_neg_param);
#endif
    return 1;
}
