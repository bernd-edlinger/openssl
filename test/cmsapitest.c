#include <string.h>

#include <openssl/cms.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "testutil.h"

static X509 *cert = NULL;
static EVP_PKEY *privkey = NULL;
static char *pwri_kek_oob_der_in = NULL;

static int test_encrypt_decrypt(void)
{
    int testresult = 0;
    STACK_OF(X509) *certstack = sk_X509_new_null();
    const char *msg = "Hello world";
    BIO *msgbio = BIO_new_mem_buf(msg, strlen(msg));
    BIO *outmsgbio = BIO_new(BIO_s_mem());
    CMS_ContentInfo* content = NULL;
    char buf[80];

    if (!TEST_ptr(certstack) || !TEST_ptr(msgbio) || !TEST_ptr(outmsgbio))
        goto end;

    if (!TEST_int_gt(sk_X509_push(certstack, cert), 0))
        goto end;

    content = CMS_encrypt(certstack, msgbio, EVP_aes_128_cbc(), CMS_TEXT);
    if (!TEST_ptr(content))
        goto end;

    if (!TEST_true(CMS_decrypt(content, privkey, cert, NULL, outmsgbio,
                               CMS_TEXT)))
        goto end;

    /* Check we got the message we first started with */
    if (!TEST_int_eq(BIO_gets(outmsgbio, buf, sizeof(buf)), strlen(msg))
            || !TEST_int_eq(strcmp(buf, msg), 0))
        goto end;

    testresult = 1;
 end:
    sk_X509_free(certstack);
    BIO_free(msgbio);
    BIO_free(outmsgbio);
    CMS_ContentInfo_free(content);

    return testresult;
}

/*
 * CMS EnvelopedData with a single PasswordRecipientInfo using
 * id-alg-PWRI-KEK and an AES-128-CFB key encryption cipher
 * (1-byte effective block size).  The encryptedKey OCTET STRING is
 * only two bytes long, so the wrapped key buffer is shorter than
 * the seven octets read by the check-byte test in kek_unwrap_key().
 * Prior to CVE-2026-9076 this triggered an out-of-bounds heap read;
 * CMS_decrypt() must now fail cleanly.
 */
static int test_pwri_kek_unwrap_short_encrypted_key(void)
{
    BIO *in = NULL;
    CMS_ContentInfo *cms = NULL;
    unsigned long err = 0;
    int ret = 0;

    if (!TEST_ptr(in = BIO_new_file(pwri_kek_oob_der_in, "rb"))
        || !TEST_ptr(cms = d2i_CMS_bio(in, NULL)))
        goto end;

    /*
     * The unwrap is attempted eagerly inside CMS_decrypt_set1_password().
     * It must fail cleanly (no OOB read) and report CMS_R_UNWRAP_FAILURE.
     */
    if (!TEST_false(CMS_decrypt_set1_password(cms,
            (unsigned char *)"password", -1)))
        goto end;

    err = ERR_peek_last_error();
    if (!TEST_int_eq(ERR_GET_LIB(err), ERR_LIB_CMS)
        || !TEST_int_eq(ERR_GET_REASON(err), CMS_R_UNWRAP_FAILURE))
        goto end;

    ERR_clear_error();
    ret = 1;
end:
    CMS_ContentInfo_free(cms);
    BIO_free(in);
    return ret;
}

int setup_tests(void)
{
    char *certin = NULL, *privkeyin = NULL;
    BIO *certbio = NULL, *privkeybio = NULL;

    if (!TEST_ptr(certin = test_get_argument(0))
            || !TEST_ptr(privkeyin = test_get_argument(1))
            || !TEST_ptr(pwri_kek_oob_der_in = test_get_argument(2)))
        return 0;

    certbio = BIO_new_file(certin, "r");
    if (!TEST_ptr(certbio))
        return 0;
    if (!TEST_true(PEM_read_bio_X509(certbio, &cert, NULL, NULL))) {
        BIO_free(certbio);
        return 0;
    }
    BIO_free(certbio);

    privkeybio = BIO_new_file(privkeyin, "r");
    if (!TEST_ptr(privkeybio)) {
        X509_free(cert);
        cert = NULL;
        return 0;
    }
    if (!TEST_true(PEM_read_bio_PrivateKey(privkeybio, &privkey, NULL, NULL))) {
        BIO_free(privkeybio);
        X509_free(cert);
        cert = NULL;
        return 0;
    }
    BIO_free(privkeybio);

    ADD_TEST(test_encrypt_decrypt);
    ADD_TEST(test_pwri_kek_unwrap_short_encrypted_key);
    return 1;
}

void cleanup_tests(void)
{
    X509_free(cert);
    EVP_PKEY_free(privkey);
}
