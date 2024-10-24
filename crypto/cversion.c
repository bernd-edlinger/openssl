/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"

#include "buildinf.h"

unsigned long OpenSSL_version_num(void)
{
    return OPENSSL_VERSION_NUMBER;
}

extern char ossl_cpu_info_str[];

const char *OpenSSL_version(int t)
{
    switch (t) {
    case OPENSSL_VERSION:
        return OPENSSL_VERSION_TEXT;
    case OPENSSL_BUILT_ON:
        return DATE;
    case OPENSSL_CFLAGS:
        return compiler_flags;
    case OPENSSL_PLATFORM:
        return PLATFORM;
    case OPENSSL_DIR:
#ifdef OPENSSLDIR
        return "OPENSSLDIR: \"" OPENSSLDIR "\"";
#else
        return "OPENSSLDIR: N/A";
#endif
    case OPENSSL_ENGINES_DIR:
#ifdef ENGINESDIR
        return "ENGINESDIR: \"" ENGINESDIR "\"";
#else
        return "ENGINESDIR: N/A";
#endif
    case OPENSSL_MODULES_DIR:
#ifdef MODULESDIR
        return "MODULESDIR: \"" MODULESDIR "\"";
#else
        return "MODULESDIR: N/A";
#endif
    case OPENSSL_CPU_INFO:
        if (OPENSSL_info(OPENSSL_INFO_CPU_SETTINGS) != NULL)
            return ossl_cpu_info_str;
        else
            return "CPUINFO: N/A";
    }
    return "not available";
}
