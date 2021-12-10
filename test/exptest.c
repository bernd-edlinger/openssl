/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "internal/nelem.h"

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include "testutil.h"

#define NUM_BITS        (BN_BITS2 * 4)

#define BN_print_var(v) test_output_bignum(#v, v)

/*
 * Test that r == 0 in test_exp_mod_zero(). Returns one on success,
 * returns zero and prints debug output otherwise.
 */
static int a_is_zero_mod_one(const char *method, const BIGNUM *r,
                             const BIGNUM *a)
{
    if (!BN_is_zero(r)) {
        TEST_error("%s failed: a ** 0 mod 1 = r (should be 0)", method);
        BN_print_var(a);
        BN_print_var(r);
        return 0;
    }
    return 1;
}

/*
 * test_mod_exp_zero tests that x**0 mod 1 == 0. It returns zero on success.
 */
static int test_mod_exp_zero(void)
{
    BIGNUM *a = NULL, *p = NULL, *m = NULL;
    BIGNUM *r = NULL;
    BN_ULONG one_word = 1;
    BN_CTX *ctx = BN_CTX_new();
    int ret = 1, failed = 0;

    if (!TEST_ptr(m = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(p = BN_new())
        || !TEST_ptr(r = BN_new()))
        goto err;

    BN_one(m);
    BN_one(a);
    BN_zero(p);

    if (!TEST_true(BN_rand(a, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY)))
        goto err;

    if (!TEST_true(BN_mod_exp(r, a, p, m, ctx)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp", r, a)))
        failed = 1;

    if (!TEST_true(BN_mod_exp_recp(r, a, p, m, ctx)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp_recp", r, a)))
        failed = 1;

    if (!TEST_true(BN_mod_exp_simple(r, a, p, m, ctx)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp_simple", r, a)))
        failed = 1;

    if (!TEST_true(BN_mod_exp_mont(r, a, p, m, ctx, NULL)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp_mont", r, a)))
        failed = 1;

    if (!TEST_true(BN_mod_exp_mont_consttime(r, a, p, m, ctx, NULL)))
        goto err;

    if (!TEST_true(a_is_zero_mod_one("BN_mod_exp_mont_consttime", r, a)))
        failed = 1;

    /*
     * A different codepath exists for single word multiplication
     * in non-constant-time only.
     */
    if (!TEST_true(BN_mod_exp_mont_word(r, one_word, p, m, ctx, NULL)))
        goto err;

    if (!TEST_BN_eq_zero(r)) {
        TEST_error("BN_mod_exp_mont_word failed: "
                   "1 ** 0 mod 1 = r (should be 0)");
        BN_print_var(r);
        goto err;
    }

    ret = !failed;
 err:
    BN_free(r);
    BN_free(a);
    BN_free(p);
    BN_free(m);
    BN_CTX_free(ctx);

    return ret;
}

static int test_mod_exp(int round)
{
    BN_CTX *ctx;
    unsigned char c;
    int ret = 0;
    BIGNUM *r_mont = NULL;
    BIGNUM *r_mont_const = NULL;
    BIGNUM *r_recp = NULL;
    BIGNUM *r_simple = NULL;
    BIGNUM *a = NULL;
    BIGNUM *b = NULL;
    BIGNUM *m = NULL;

    if (!TEST_ptr(ctx = BN_CTX_new()))
        goto err;

    if (!TEST_ptr(r_mont = BN_new())
        || !TEST_ptr(r_mont_const = BN_new())
        || !TEST_ptr(r_recp = BN_new())
        || !TEST_ptr(r_simple = BN_new())
        || !TEST_ptr(a = BN_new())
        || !TEST_ptr(b = BN_new())
        || !TEST_ptr(m = BN_new()))
        goto err;

    if (!TEST_true(RAND_bytes(&c, 1)))
        goto err;
    c = (c % BN_BITS) - BN_BITS2;
    if (!TEST_true(BN_rand(a, NUM_BITS + c, BN_RAND_TOP_ONE,
                           BN_RAND_BOTTOM_ANY)))
        goto err;

    if (!TEST_true(RAND_bytes(&c, 1)))
        goto err;
    c = (c % BN_BITS) - BN_BITS2;
    if (!TEST_true(BN_rand(b, NUM_BITS + c, BN_RAND_TOP_ONE,
                           BN_RAND_BOTTOM_ANY)))
        goto err;

    if (!TEST_true(RAND_bytes(&c, 1)))
        goto err;
    c = (c % BN_BITS) - BN_BITS2;
    if (!TEST_true(BN_rand(m, NUM_BITS + c, BN_RAND_TOP_ONE,
                           BN_RAND_BOTTOM_ODD)))
        goto err;

    if (!TEST_true(BN_mod(a, a, m, ctx))
        || !TEST_true(BN_mod(b, b, m, ctx))
        || !TEST_true(BN_mod_exp_mont(r_mont, a, b, m, ctx, NULL))
        || !TEST_true(BN_mod_exp_recp(r_recp, a, b, m, ctx))
        || !TEST_true(BN_mod_exp_simple(r_simple, a, b, m, ctx))
        || !TEST_true(BN_mod_exp_mont_consttime(r_mont_const, a, b, m, ctx, NULL)))
        goto err;

    if (!TEST_BN_eq(r_simple, r_mont)
        || !TEST_BN_eq(r_simple, r_recp)
        || !TEST_BN_eq(r_simple, r_mont_const)) {
        if (BN_cmp(r_simple, r_mont) != 0)
            TEST_info("simple and mont results differ");
        if (BN_cmp(r_simple, r_mont_const) != 0)
            TEST_info("simple and mont const time results differ");
        if (BN_cmp(r_simple, r_recp) != 0)
            TEST_info("simple and recp results differ");

        BN_print_var(a);
        BN_print_var(b);
        BN_print_var(m);
        BN_print_var(r_simple);
        BN_print_var(r_recp);
        BN_print_var(r_mont);
        BN_print_var(r_mont_const);
        goto err;
    }

    ret = 1;
 err:
    BN_free(r_mont);
    BN_free(r_mont_const);
    BN_free(r_recp);
    BN_free(r_simple);
    BN_free(a);
    BN_free(b);
    BN_free(m);
    BN_CTX_free(ctx);

    return ret;
}

static int test_mod_exp_x2(int idx)
{
    BN_CTX *ctx;
    int ret = 0;
    BIGNUM *r_mont_const_x2_1 = NULL;
    BIGNUM *r_mont_const_x2_2 = NULL;
    BIGNUM *r_simple1 = NULL;
    BIGNUM *r_simple2 = NULL;
    BIGNUM *a1 = NULL;
    BIGNUM *b1 = NULL;
    BIGNUM *m1 = NULL;
    BIGNUM *a2 = NULL;
    BIGNUM *b2 = NULL;
    BIGNUM *m2 = NULL;
    int factor_size = 0;

    if (idx <= 100)
        factor_size = 1024;
    else if (idx <= 200)
        factor_size = 1536;
    else if (idx <= 300)
        factor_size = 2048;

    if (!TEST_ptr(ctx = BN_CTX_new()))
        goto err;

    if (!TEST_ptr(r_mont_const_x2_1 = BN_new())
        || !TEST_ptr(r_mont_const_x2_2 = BN_new())
        || !TEST_ptr(r_simple1 = BN_new())
        || !TEST_ptr(r_simple2 = BN_new())
        || !TEST_ptr(a1 = BN_new())
        || !TEST_ptr(b1 = BN_new())
        || !TEST_ptr(m1 = BN_new())
        || !TEST_ptr(a2 = BN_new())
        || !TEST_ptr(b2 = BN_new())
        || !TEST_ptr(m2 = BN_new()))
        goto err;

#ifdef __GNUC__
# pragma GCC diagnostic ignored "-Woverlength-strings"
#endif
if (factor_size == 2048) {
    /*
       replace random values with test values from
       https://github.com/bernd-edlinger/openssl/runs/4480121928?check_suite_focus=true#step:10:136
    */
    BN_hex2bn(&a1, "95564994a96c45954227b845a1e99cb939d5a1da99ee91acc962396ae999a9ee"
        "38603790448f2f7694c242a875f0cad0aae658eba085f312d2febbbd128dd2b5"
        "8f7d1149f03724215d704344d0d62c587ae3c5939cba4b9b5f3dc5e8e911ef9a"
        "5ce1a5a749a4989d0d8368f6e1f8cdf3a362a6c97fb02047ff152b480a4ad985"
        "2d45efdf0770542992afca6a0590d52930434bba96017afbc9f99e112950a8b1"
        "a359473ec376f329bdae6a19f503be6d4be7393c4e43468831234e27e3838680"
        "b949390d2e416a3f9759e5349ab4c253f6f29f819a6fe4cbfd27ada34903300e"
        "da021f62839f5878a36f1bc3085375b00fd5fa3e68d316c0fdace87a97558465");
    BN_hex2bn(&b1, "f95dc0f980fbd22e90caa5a387cc4a369f3f830d50dd321c40db8c09a7e1a241"
        "a536e096622d3280c0c1ba849c1f4a79bf490f60006d081e8cf69960189f0d31"
        "2cd9e17073a3fba7881b21474a13b334116cb2f5dbf3189a6de3515d0840f053"
        "c776d3982d391b6d04d642dda5cc6d1640174c09875addb70595658f89efb439"
        "dc6fbd55f903aadd307982d3f659207f265e1ec6271b274521b7a5e28e8fd7a5"
        "5df089292820477802a43cf5b6b94e999e8c9944ddebb0d0e95a60f88cb7e813"
        "ba110d20e1024774107dd02949031864923b3cb8c3f7250d6d1287b0a40db6a4"
        "7bd5a469518eb65aa207ddc47d8c6e5fc8e0c105be8fc1d4b57b2e27540471d5");
    BN_hex2bn(&m1, "fef15d5ce4625f1bccfbba49fc8439c72bf8202af039a2259678941b60bb4a8f"
        "2987e965d58fd8cf86a856674d519763d0e1211cc9f8596971050d56d9b35db3"
        "785866cfbca17cfdbed6060be3629d894f924a89fdc1efc624f80d41a22f1900"
        "9503fcc3824ef62ccb9208430c26f2d8ceb2c63488ec4c07437aa4c96c43dd8b"
        "9289ed00a712ff66ee195dc71f5e4ead02172b63c543d69baf495f5fd63ba7bc"
        "c633bd309c016e37736da92129d0b053d4ab28d21ad7d8b6fab2a8bbdc8ee647"
        "d2fbcf2cf426cf892e6f5639e0252993965dfb73ccd277407014ea784aaa280c"
        "b7b03972bc8b0baa72360bdb44b82415b86b2f260f877791cd33ba8f2d65229b");
    BN_hex2bn(&a2, "5f412492c2fa14ec42aa14553d44cc13e9e209061c781b92ea83e7728b72f1b6"
        "382a53b91fb0505899e11c4530e4d90459207f02ad894d55d6e11c6443495cef"
        "104a2ab8294f8c683db08c091efdac5d4273865343e96bf6e7fbb970cb0806c9"
        "9177045d8810d1d4d00f735bfaa6e216c53b23aee88b6ec714c3f82a978465db"
        "0a14e1260d4191e90d23c81872150cafdd2953956f2735b3ff2b6afea6324564"
        "a322b8412f0944a032d27a450415573ae5dbef94ca0fc6ca600078ee1e75e9ea"
        "576aef6d16469feff33ffbbab6cbb1eca595c7bddef46f575b72a388d4a552bd"
        "486aa5bf33bdda938896acf682d3f1d6e2822b43c115c94ae21f3ab99f57dc9e");
    BN_hex2bn(&b2, "4d3236b30ad225dbef1bf9d54ed40ed0fc0ea30ef9ba56e58c45576cc2f1aeda"
        "28a628b59a074c96136a39c5446980bf5b7f64218fa1101b0f1a76457fd6fad7"
        "457775cac864880dcc2a321b429c702082cf8cc6018ee3d76dccbe5afb04365f"
        "251837e0416712f01d05ee895e24bc1fe45a958caba3cab636e3b203d8badf52"
        "a2466817622e565509140f375c907d94c568fd241adfdc87fd96c3afeb0befa5"
        "1fffbd8d800457a882a28a799f07998b2a9e8461cf92dde253724b87ecea3ace"
        "83089d1a430f997ef6c61c57d79eb87a1063810c30cca2824abdd871b9e0d661"
        "cc968679fb687d9dc1df1e3124ff4b80a99a6d68edc4edcdc7c600bc6cb6e4be");
   BN_hex2bn(&m2, "8f0287128bb6f5ce6e51cdf3de6d66c425c92caa9d9d3a2278681af38f285cf6"
        "beed68a3ab5a25fc7b3bde57514d07885da42e3d03cf62d8edd54609fb5fe3b5"
        "1bee6623b86c8afbcedd4e68f814886bc2f24b0d7da2afe6421e63e3c2c1ef32"
        "50ec69ccaa1d0f7825d04a7d4469ecf88e0c5c230a7f255ca8abbcabaf4d2b5b"
        "a4516363584f1b4275a570591f7523caf02cba3a9d1593ba9e26c31b686b7bda"
        "6454a036d8868c9d10e4df3cb71998db56fe0e60b9df5799a8f18396811bcb06"
        "01567a7f47299247769635107b267c4e0146a42a83a5a752d428933fbf100e6d"
        "934a884f338ab98850810ccf6d056764807afcdded8ce6a85bf4d7810083a969");
} else {
    BN_rand(a1, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_rand(b1, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_rand(m1, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    BN_rand(a2, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_rand(b2, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
    BN_rand(m2, factor_size, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
}

    if (!TEST_true(BN_mod(a1, a1, m1, ctx))
        || !TEST_true(BN_mod(b1, b1, m1, ctx))
        || !TEST_true(BN_mod(a2, a2, m2, ctx))
        || !TEST_true(BN_mod(b2, b2, m2, ctx))
        || !TEST_true(BN_mod_exp_simple(r_simple1, a1, b1, m1, ctx))
        || !TEST_true(BN_mod_exp_simple(r_simple2, a2, b2, m2, ctx))
        || !TEST_true(BN_mod_exp_mont_consttime_x2(r_mont_const_x2_1, a1, b1, m1, NULL,
                                                   r_mont_const_x2_2, a2, b2, m2, NULL,
                                                   ctx)))
        goto err;

    if (!TEST_BN_eq(r_simple1, r_mont_const_x2_1)
        || !TEST_BN_eq(r_simple2, r_mont_const_x2_2)) {
        if (BN_cmp(r_simple1, r_mont_const_x2_1) != 0)
            TEST_info("simple and mont const time x2 (#1) results differ");
        if (BN_cmp(r_simple2, r_mont_const_x2_2) != 0)
            TEST_info("simple and mont const time x2 (#2) results differ");

        BN_print_var(a1);
        BN_print_var(b1);
        BN_print_var(m1);
        BN_print_var(a2);
        BN_print_var(b2);
        BN_print_var(m2);
        BN_print_var(r_simple1);
        BN_print_var(r_simple2);
        BN_print_var(r_mont_const_x2_1);
        BN_print_var(r_mont_const_x2_2);
        goto err;
    }

    ret = 1;
 err:
    BN_free(r_mont_const_x2_1);
    BN_free(r_mont_const_x2_2);
    BN_free(r_simple1);
    BN_free(r_simple2);
    BN_free(a1);
    BN_free(b1);
    BN_free(m1);
    BN_free(a2);
    BN_free(b2);
    BN_free(m2);
    BN_CTX_free(ctx);

    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_mod_exp_zero);
    ADD_ALL_TESTS(test_mod_exp, 200);
    ADD_ALL_TESTS(test_mod_exp_x2, 300);
    return 1;
}
