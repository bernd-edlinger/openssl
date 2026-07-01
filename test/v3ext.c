/*
 * Copyright 2016-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include "internal/nelem.h"

#include "testutil.h"

static const char *infile;

static int test_pathlen(void)
{
    X509 *x = NULL;
    BIO *b = NULL;
    long pathlen;
    int ret = 0;

    if (!TEST_ptr(b = BIO_new_file(infile, "r"))
            || !TEST_ptr(x = PEM_read_bio_X509(b, NULL, NULL, NULL))
            || !TEST_int_eq(pathlen = X509_get_pathlen(x), 6))
        goto end;

    ret = 1;

end:
    BIO_free(b);
    X509_free(x);
    return ret;
}

static int test_custom_ext(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    X509_NAME *name = NULL;
    X509_EXTENSION *ex = NULL;
    int nid = 0;
    int ret = 0;

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL))
            || !TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0)
            || !TEST_int_gt(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 512), 0)
            || !TEST_int_gt(EVP_PKEY_keygen(ctx, &pkey), 0)
            || !TEST_ptr(x509 = X509_new()))
        goto err;

    if (!TEST_true(X509_set_version(x509, 2)) /* version 3 certificate */
            || !TEST_true(ASN1_INTEGER_set(X509_get_serialNumber(x509), 12345))
            || !TEST_true(X509_gmtime_adj(X509_getm_notBefore(x509), 0))
            || !TEST_true(X509_gmtime_adj(X509_getm_notAfter(x509),
                                          (long)60 * 60 * 34 * 365))
            || !TEST_true(X509_set_pubkey(x509, pkey)))
        goto err;

    if (!TEST_ptr(name = X509_get_subject_name(x509))
            || !TEST_true(X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                                                     (unsigned char *)"EU",
                                                     -1, -1, 0))
            || !TEST_true(X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                                                     (unsigned char *)"Test",
                                                     -1, -1, 0))
            || !TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                                     (unsigned char *)"MyCA",
                                                     -1, -1, 0))
            || !TEST_true(X509_set_issuer_name(x509, name)))
        goto err;

    /*
     * Add extension using V3 code: we can set the config file as NULL
     * because we wont reference any other sections. We can also set the
     * context to NULL because none of these extensions below will need to
     * access it.
     */
    if (!TEST_ptr(ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_cert_type,
                                           "server"))
            || !TEST_true(X509_add_ext(x509, ex, -1)))
        goto err;

    X509_EXTENSION_free(ex);
    ex = NULL;

    if (!TEST_ptr(ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment,
                                           "example comment extension"))
            || !TEST_true(X509_add_ext(x509, ex, -1)))
        goto err;

    X509_EXTENSION_free(ex);
    ex = NULL;

    if (!TEST_ptr(ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
                                           "critical,CA:TRUE"))
            || !TEST_true(X509_add_ext(x509, ex, -1)))
        goto err;

    X509_EXTENSION_free(ex);
    ex = NULL;

    if (!TEST_true(nid = OBJ_create("1.2.3.4.5.6", "MyAlias",
                                    "My Test Alias Extension"))
            || !TEST_true(X509V3_EXT_add_alias(nid, NID_netscape_comment))
            || !TEST_ptr(ex = X509V3_EXT_conf_nid(NULL, NULL, nid,
                                                  "example comment alias"))
            || !TEST_true(X509_add_ext(x509, ex, -1)))
        goto err;

    if (!TEST_true(X509_sign(x509, pkey, EVP_sha1()))
            || !TEST_true(X509_print_fp(stdout, x509))
            || !TEST_true(PEM_write_X509(stdout, x509))
            || !TEST_true(PEM_write_PrivateKey(stdout, pkey, NULL, NULL,
                                               0, NULL, NULL)))
        goto err;

    ret = 1;

err:
    X509_EXTENSION_free(ex);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    X509V3_EXT_cleanup();
    return ret;
}

#ifndef OPENSSL_NO_RFC3779
static int test_asid(void)
{
    ASN1_INTEGER *val1 = NULL, *val2 = NULL;
    ASIdentifiers *asid1 = ASIdentifiers_new(), *asid2 = ASIdentifiers_new(),
                  *asid3 = ASIdentifiers_new(), *asid4 = ASIdentifiers_new();
    int testresult = 0;

    if (!TEST_ptr(asid1)
            || !TEST_ptr(asid2)
            || !TEST_ptr(asid3))
        goto err;

    if (!TEST_ptr(val1 = ASN1_INTEGER_new())
            || !TEST_true(ASN1_INTEGER_set_int64(val1, 64496)))
        goto err;

    if (!TEST_true(X509v3_asid_add_id_or_range(asid1, V3_ASID_ASNUM, val1, NULL)))
        goto err;

    val1 = NULL;
    if (!TEST_ptr(val2 = ASN1_INTEGER_new())
            || !TEST_true(ASN1_INTEGER_set_int64(val2, 64497)))
        goto err;

    if (!TEST_true(X509v3_asid_add_id_or_range(asid2, V3_ASID_ASNUM, val2, NULL)))
        goto err;

    val2 = NULL;
    if (!TEST_ptr(val1 = ASN1_INTEGER_new())
            || !TEST_true(ASN1_INTEGER_set_int64(val1, 64496))
            || !TEST_ptr(val2 = ASN1_INTEGER_new())
            || !TEST_true(ASN1_INTEGER_set_int64(val2, 64497)))
        goto err;

    /*
     * Just tests V3_ASID_ASNUM for now. Could be extended at some point to also
     * test V3_ASID_RDI if we think it is worth it.
     */
    if (!TEST_true(X509v3_asid_add_id_or_range(asid3, V3_ASID_ASNUM, val1, val2)))
        goto err;
    val1 = val2 = NULL;

    /* Actual subsets */
    if (!TEST_true(X509v3_asid_subset(NULL, NULL))
            || !TEST_true(X509v3_asid_subset(NULL, asid1))
            || !TEST_true(X509v3_asid_subset(asid1, asid1))
            || !TEST_true(X509v3_asid_subset(asid2, asid2))
            || !TEST_true(X509v3_asid_subset(asid1, asid3))
            || !TEST_true(X509v3_asid_subset(asid2, asid3))
            || !TEST_true(X509v3_asid_subset(asid3, asid3))
            || !TEST_true(X509v3_asid_subset(asid4, asid1))
            || !TEST_true(X509v3_asid_subset(asid4, asid2))
            || !TEST_true(X509v3_asid_subset(asid4, asid3)))
        goto err;

    /* Not subsets */
    if (!TEST_false(X509v3_asid_subset(asid1, NULL))
            || !TEST_false(X509v3_asid_subset(asid1, asid2))
            || !TEST_false(X509v3_asid_subset(asid2, asid1))
            || !TEST_false(X509v3_asid_subset(asid3, asid1))
            || !TEST_false(X509v3_asid_subset(asid3, asid2))
            || !TEST_false(X509v3_asid_subset(asid1, asid4))
            || !TEST_false(X509v3_asid_subset(asid2, asid4))
            || !TEST_false(X509v3_asid_subset(asid3, asid4)))
        goto err;

    testresult = 1;
 err:
    ASN1_INTEGER_free(val1);
    ASN1_INTEGER_free(val2);
    ASIdentifiers_free(asid1);
    ASIdentifiers_free(asid2);
    ASIdentifiers_free(asid3);
    ASIdentifiers_free(asid4);
    return testresult;
}

static struct ip_ranges_st {
    const unsigned int afi;
    const char *ip1;
    const char *ip2;
    int rorp;
} ranges[] = {
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.0.1", IPAddressOrRange_addressPrefix},
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.0.2", IPAddressOrRange_addressRange},
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.0.3", IPAddressOrRange_addressPrefix},
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.0.254", IPAddressOrRange_addressRange},
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.0.255", IPAddressOrRange_addressPrefix},
    { IANA_AFI_IPV4, "192.168.0.1", "192.168.0.255", IPAddressOrRange_addressRange},
    { IANA_AFI_IPV4, "192.168.0.1", "192.168.0.1", IPAddressOrRange_addressPrefix},
    { IANA_AFI_IPV4, "192.168.0.0", "192.168.255.255", IPAddressOrRange_addressPrefix},
    { IANA_AFI_IPV4, "192.168.1.0", "192.168.255.255", IPAddressOrRange_addressRange},
    { IANA_AFI_IPV6, "2001:0db8::0", "2001:0db8::1", IPAddressOrRange_addressPrefix},
    { IANA_AFI_IPV6, "2001:0db8::0", "2001:0db8::2", IPAddressOrRange_addressRange},
    { IANA_AFI_IPV6, "2001:0db8::0", "2001:0db8::3", IPAddressOrRange_addressPrefix},
    { IANA_AFI_IPV6, "2001:0db8::0", "2001:0db8::fffe", IPAddressOrRange_addressRange},
    { IANA_AFI_IPV6, "2001:0db8::0", "2001:0db8::ffff", IPAddressOrRange_addressPrefix},
    { IANA_AFI_IPV6, "2001:0db8::1", "2001:0db8::ffff", IPAddressOrRange_addressRange},
    { IANA_AFI_IPV6, "2001:0db8::1", "2001:0db8::1", IPAddressOrRange_addressPrefix},
    { IANA_AFI_IPV6, "2001:0db8::0:0", "2001:0db8::ffff:ffff", IPAddressOrRange_addressPrefix},
    { IANA_AFI_IPV6, "2001:0db8::1:0", "2001:0db8::ffff:ffff", IPAddressOrRange_addressRange}
};

static int check_addr(IPAddrBlocks *addr, int type)
{
    IPAddressFamily *fam;
    IPAddressOrRange *aorr;

    if (!TEST_int_eq(sk_IPAddressFamily_num(addr), 1))
        return 0;

    fam = sk_IPAddressFamily_value(addr, 0);
    if (!TEST_ptr(fam))
        return 0;

    if (!TEST_int_eq(fam->ipAddressChoice->type, IPAddressChoice_addressesOrRanges))
        return 0;

    if (!TEST_int_eq(sk_IPAddressOrRange_num(fam->ipAddressChoice->u.addressesOrRanges), 1))
        return 0;

    aorr = sk_IPAddressOrRange_value(fam->ipAddressChoice->u.addressesOrRanges, 0);
    if (!TEST_ptr(aorr))
        return 0;

    if (!TEST_int_eq(aorr->type, type))
        return 0;

    return 1;
}

static int test_addr_ranges(void)
{
    IPAddrBlocks *addr = NULL;
    ASN1_OCTET_STRING *ip1 = NULL, *ip2 = NULL;
    size_t i;
    int testresult = 0;

    for (i = 0; i < OSSL_NELEM(ranges); i++) {
        addr = sk_IPAddressFamily_new_null();
        if (!TEST_ptr(addr))
            goto end;
        /*
         * Has the side effect of installing the comparison function onto the
         * stack.
         */
        if (!TEST_true(X509v3_addr_canonize(addr)))
            goto end;

        ip1 = a2i_IPADDRESS(ranges[i].ip1);
        if (!TEST_ptr(ip1))
            goto end;
        if (!TEST_true(ip1->length == 4 || ip1->length == 16))
            goto end;
        ip2 = a2i_IPADDRESS(ranges[i].ip2);
        if (!TEST_ptr(ip2))
            goto end;
        if (!TEST_int_eq(ip2->length, ip1->length))
            goto end;
        if (!TEST_true(memcmp(ip1->data, ip2->data, ip1->length) <= 0))
            goto end;

        if (!TEST_true(X509v3_addr_add_range(addr, ranges[i].afi, NULL, ip1->data, ip2->data)))
            goto end;

        if (!TEST_true(X509v3_addr_is_canonical(addr)))
            goto end;

        if (!check_addr(addr, ranges[i].rorp))
            goto end;

        sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
        addr = NULL;
        ASN1_OCTET_STRING_free(ip1);
        ASN1_OCTET_STRING_free(ip2);
        ip1 = ip2 = NULL;
    }

    testresult = 1;
 end:
    sk_IPAddressFamily_pop_free(addr, IPAddressFamily_free);
    ASN1_OCTET_STRING_free(ip1);
    ASN1_OCTET_STRING_free(ip2);
    return testresult;
}

static struct extvalues_st {
    const char *value;
    int pass;
} extvalues[] = {
    /* No prefix is ok */
    { "sbgp-ipAddrBlock = IPv4:192.0.0.1\n", 1 },
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0/0\n", 1 },
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0/1\n", 1 },
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0/32\n", 1 },
    /* Prefix is too long */
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0/33\n", 0 },
    /* Unreasonably large prefix */
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0/12341234\n", 0 },
    /* Invalid IP addresses */
    { "sbgp-ipAddrBlock = IPv4:192.0.0\n", 0 },
    { "sbgp-ipAddrBlock = IPv4:256.0.0.0\n", 0 },
    { "sbgp-ipAddrBlock = IPv4:-1.0.0.0\n", 0 },
    { "sbgp-ipAddrBlock = IPv4:192.0.0.0.0\n", 0 },
    { "sbgp-ipAddrBlock = IPv3:192.0.0.0\n", 0 },

    /* IPv6 */
    /* No prefix is ok */
    { "sbgp-ipAddrBlock = IPv6:2001:db8::\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001::db8\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:0db8:0000:0000:0000:0000:0000:0000\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/0\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/1\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/32\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:0db8:0000:0000:0000:0000:0000:0000/32\n", 1 },
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/128\n", 1 },
    /* Prefix is too long */
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/129\n", 0 },
    /* Unreasonably large prefix */
    { "sbgp-ipAddrBlock = IPv6:2001:db8::/12341234\n", 0 },
    /* Invalid IP addresses */
    /* Not enough blocks of numbers */
    { "sbgp-ipAddrBlock = IPv6:2001:0db8:0000:0000:0000:0000:0000\n", 0 },
    /* Too many blocks of numbers */
    { "sbgp-ipAddrBlock = IPv6:2001:0db8:0000:0000:0000:0000:0000:0000:0000\n", 0 },
    /* First value too large */
    { "sbgp-ipAddrBlock = IPv6:1ffff:0db8:0000:0000:0000:0000:0000:0000\n", 0 },
    /* First value with invalid characters */
    { "sbgp-ipAddrBlock = IPv6:fffg:0db8:0000:0000:0000:0000:0000:0000\n", 0 },
    /* First value is negative */
    { "sbgp-ipAddrBlock = IPv6:-1:0db8:0000:0000:0000:0000:0000:0000\n", 0 }
};

static int test_ext_syntax(void)
{
    size_t i;
    int testresult = 1;

    for (i = 0; i < OSSL_NELEM(extvalues); i++) {
        X509V3_CTX ctx;
        BIO *extbio = BIO_new_mem_buf(extvalues[i].value,
                                      strlen(extvalues[i].value));
        CONF *conf;
        long eline;

        if (!TEST_ptr(extbio))
            return 0 ;

        conf = NCONF_new(NULL);
        if (!TEST_ptr(conf)) {
            BIO_free(extbio);
            return 0;
        }
        if (!TEST_long_gt(NCONF_load_bio(conf, extbio, &eline), 0)) {
            testresult = 0;
        } else {
            X509V3_set_ctx_test(&ctx);
            X509V3_set_nconf(&ctx, conf);

            if (extvalues[i].pass) {
                if (!TEST_true(X509V3_EXT_add_nconf(conf, &ctx, "default",
                                                    NULL))) {
                    TEST_info("Value: %s", extvalues[i].value);
                    testresult = 0;
                }
            } else {
                ERR_set_mark();
                if (!TEST_false(X509V3_EXT_add_nconf(conf, &ctx, "default",
                                                     NULL))) {
                    testresult = 0;
                    TEST_info("Value: %s", extvalues[i].value);
                    ERR_clear_last_mark();
                } else {
                    ERR_pop_to_mark();
                }
            }
        }
        BIO_free(extbio);
        NCONF_free(conf);
    }

    return testresult;
}
#endif /* OPENSSL_NO_RFC3779 */

/*
 * nameConstraints extnValue contents with one empty directoryName subtree.
 * Empty X509_NAME has canon_enc == NULL / canon_enclen == 0.
 *
 *   SEQUENCE { [0|1] { SEQUENCE { [4] { SEQUENCE {} } } } }
 */
static const unsigned char nc_excluded_empty_dirname[] = {
    0x30, 0x08, 0xa1, 0x06, 0x30, 0x04, 0xa4, 0x02, 0x30, 0x00
};
static const unsigned char nc_permitted_empty_dirname[] = {
    0x30, 0x08, 0xa0, 0x06, 0x30, 0x04, 0xa4, 0x02, 0x30, 0x00
};

/* Decode a raw nameConstraints extnValue into a NAME_CONSTRAINTS object. */
static NAME_CONSTRAINTS *nc_empty_dirname_from_der(const unsigned char *der,
    unsigned int der_len)
{
    NAME_CONSTRAINTS *nc = NULL;
    ASN1_OCTET_STRING *os = NULL;
    X509_EXTENSION *ext = NULL;

    os = ASN1_OCTET_STRING_new();
    if (!TEST_ptr(os)
        || !TEST_true(ASN1_OCTET_STRING_set(os, der, der_len)))
        goto end;
    ext = X509_EXTENSION_create_by_NID(NULL, NID_name_constraints,
        1 /* critical */, os);
    if (!TEST_ptr(ext))
        goto end;
    nc = X509V3_EXT_d2i(ext);

end:
    X509_EXTENSION_free(ext);
    ASN1_OCTET_STRING_free(os);
    return nc;
}

/* Build a minimal certificate with a non-empty subject DN. */
static X509 *nc_empty_dirname_subject(const char *cn)
{
    X509 *x = NULL;
    X509_NAME *nm = NULL;

    if (!TEST_ptr(x = X509_new()))
        goto err;
    nm = X509_NAME_new();
    if (!TEST_ptr(nm)
        || !TEST_true(X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
            (const unsigned char *)cn, -1, -1, 0))
        || !TEST_true(X509_set_subject_name(x, nm)))
        goto err;
    X509_NAME_free(nm);
    return x;

err:
    X509_NAME_free(nm);
    X509_free(x);
    return NULL;
}

/* Check an empty directoryName constraint against a non-empty subject DN. */
static int nc_check_empty_dirname(const unsigned char *der, unsigned int der_len,
    int expected)
{
    int ok = 0;
    NAME_CONSTRAINTS *nc = NULL;
    X509 *x = NULL;

    if (!TEST_ptr(nc = nc_empty_dirname_from_der(der, der_len))
        || !TEST_ptr(x = nc_empty_dirname_subject("leaf.example"))
        || !TEST_int_eq(NAME_CONSTRAINTS_check(x, nc), expected))
        goto end;

    ok = 1;

end:
    X509_free(x);
    NAME_CONSTRAINTS_free(nc);
    return ok;
}

/* Empty excluded directoryName matches the subject DN: excluded violation. */
static int test_nc_empty_dirname_excluded(void)
{
    return nc_check_empty_dirname(nc_excluded_empty_dirname,
        sizeof(nc_excluded_empty_dirname), X509_V_ERR_EXCLUDED_VIOLATION);
}

/* Empty permitted directoryName matches the subject DN: permitted. */
static int test_nc_empty_dirname_permitted(void)
{
    return nc_check_empty_dirname(nc_permitted_empty_dirname,
        sizeof(nc_permitted_empty_dirname), X509_V_OK);
}

int setup_tests(void)
{
    if (!TEST_ptr(infile = test_get_argument(0)))
        return 0;

    ADD_TEST(test_pathlen);
    ADD_TEST(test_custom_ext);
#ifndef OPENSSL_NO_RFC3779
    ADD_TEST(test_asid);
    ADD_TEST(test_addr_ranges);
    ADD_TEST(test_ext_syntax);
#endif /* OPENSSL_NO_RFC3779 */
    ADD_TEST(test_nc_empty_dirname_excluded);
    ADD_TEST(test_nc_empty_dirname_permitted);
    return 1;
}
