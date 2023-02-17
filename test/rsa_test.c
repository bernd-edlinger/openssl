#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#ifdef OPENSSL_NO_RSA
int main(int argc, char *argv[])
{
    printf("No RSA support\n");
    return (0);
}
#else
# include <openssl/rsa.h>

static unsigned long lsqrt(unsigned long x)
{
   unsigned long res0;
   unsigned long res1 = 1;
   do {
     res0 = res1;
     res1 = (x/res0 + res0)/2;
   } while (res0 != res1 && res0 != res1+1);
   return res1;
}

static unsigned long lsqr(unsigned long x)
{
    return x*x;
}

int main(int argc, char *argv[])
{
    int err = 0;
    RSA *key = NULL;
    unsigned char ptext[2048];
    unsigned char ctext[2048];
    unsigned char ptext_ex[2048];
    int klen = 2048;
    int non_blind = 0;
    int pubkey = 0;
    int clen;
    int num;
    int n, v, ex;
    struct timespec t1, t2;
    unsigned long min, max, avg, avg2;

    for (n = 1; n < argc; n++) {
        if (argv[n][0] >= '0' && argv[n][0] <= '9')
            klen = atoi(argv[n]);
        else if (!strcmp(argv[n], "-non_blind"))
            non_blind = 1;
        else if (!strcmp(argv[n], "-pubkey"))
            pubkey = 1;
        else {
            klen = -1;
            break;
        }
    }

    if (klen < 512 || klen > 16384) {
        printf("usage: rsa_test [<rsa> [-non_blind|-pubkey]]\n");
        goto err;
    }

    key = RSA_generate_key(klen, 0x10001, NULL, NULL);
    if (key == NULL) {
        printf("RSA_generate_key failed!\n");
        err = 1;
        goto err;
    }

    printf("RSA: %d\n", klen);
    clen = RSA_size(key);
    if (non_blind) {
        printf("blinding off\n");
        RSA_blinding_off(key);
    }

    for (v = 0; v < 60; v++) {
        memset(ptext_ex, 0, sizeof(ptext_ex));
        memset(ptext_ex + v, 0xAA, clen - v);
        if (v == 0)
            ptext_ex[0] |= 0x88u >> ((-klen) & 7);
        ptext_ex[0] &= 0x8Fu >> ((-klen) & 7);
        ptext_ex[1] &= 0xFFFu >> ((-klen) & 7);
        if (pubkey)
            num = RSA_public_encrypt(clen, ptext_ex, ctext, key,
                                     RSA_NO_PADDING);
        else {
            RSA *key1 = RSAPublicKey_dup(key);
            if (key1 == NULL) {
                printf("RSAPublickey_dup failed!\n");
                err = 1;
                goto err;
            }
            num = RSA_public_encrypt(clen, ptext_ex, ctext, key1,
                                     RSA_NO_PADDING);
            RSA_free(key1);
        }
        if (num != clen) {
            printf("RSA_NO_PADDING encryption failed!\n");
            err = 1;
            goto err;
        }

        min = -1;
        max = 0;
        avg = 0;
        avg2 = 0;
        ex = 0;
        for (n = 0; n < 1032; n++) {
            clock_gettime(CLOCK_MONOTONIC, &t1);
            num = RSA_private_decrypt(num, ctext, ptext, key, RSA_NO_PADDING);
            clock_gettime(CLOCK_MONOTONIC, &t2);
            if (t1.tv_sec != t2.tv_sec)
                t2.tv_nsec += 1000000000;
            t2.tv_nsec -= t1.tv_nsec;
            avg += t2.tv_nsec;
            avg2 += lsqr(t2.tv_nsec);
            if (t2.tv_nsec < min)
                min = t2.tv_nsec;
            if (t2.tv_nsec > max)
                max = t2.tv_nsec;
            if (n >= 32 && t2.tv_nsec >= (min + max)/2)
                ex++;
            if (num != clen || memcmp(ptext, ptext_ex, num) != 0) {
                printf("RSA_NO_PADDING decryption failed!\n");
                err = 1;
                goto err;
            }
        }

        printf("v=%.2d: min=%8ld max=%8ld avg=%8ld var=%8ld ex=%d\n",
               v, min, max, avg / n, lsqrt(avg2/n - lsqr(avg/n)), ex);
    }

err:
    RSA_free(key);
    return err;
}
#endif
