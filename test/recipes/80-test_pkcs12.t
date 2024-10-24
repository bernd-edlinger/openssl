#! /usr/bin/env perl
# Copyright 2016-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use OpenSSL::Test qw/:DEFAULT srctop_file with/;
use OpenSSL::Test::Utils;

use Encode;

setup("test_pkcs12");

plan skip_all => "The PKCS12 command line utility is not supported by this OpenSSL build"
    if disabled("des");

my $pass = "σύνθημα γνώρισμα";

my $savedcp;
if (eval { require Win32::API; 1; }) {
    # Trouble is that Win32 perl uses CreateProcessA, which
    # makes it problematic to pass non-ASCII arguments, from perl[!]
    # that is. This is because CreateProcessA is just a wrapper for
    # CreateProcessW and will call MultiByteToWideChar and use
    # system default locale. Since we attempt Greek pass-phrase
    # conversion can be done only with Greek locale.

    Win32::API->Import("kernel32","UINT GetSystemDefaultLCID()");
    if (GetSystemDefaultLCID() != 0x408) {
        plan skip_all => "Non-Greek system locale";
    } else {
        # Ensure correct code page so that VERBOSE output is right.
        Win32::API->Import("kernel32","UINT GetConsoleOutputCP()");
        Win32::API->Import("kernel32","BOOL SetConsoleOutputCP(UINT cp)");
        $savedcp = GetConsoleOutputCP();
        SetConsoleOutputCP(1253);
        $pass = Encode::encode("cp1253",Encode::decode("utf-8",$pass));
    }
} elsif ($^O eq "MSWin32") {
    plan skip_all => "Win32::API unavailable";
} else {
    # Running MinGW tests transparently under Wine apparently requires
    # UTF-8 locale...

    foreach(`locale -a`) {
        s/\R$//;
        if ($_ =~ m/^C\.UTF\-?8/i) {
            $ENV{LC_ALL} = $_;
            last;
        }
    }
}
$ENV{OPENSSL_WIN32_UTF8}=1;

plan tests => 8;

# just see that we can read shibboleth.pfx protected with $pass
ok(run(app(["openssl", "pkcs12", "-noout",
            "-password", "pass:$pass",
            "-in", srctop_file("test", "shibboleth.pfx")])),
   "test_pkcs12");

# Test some bad pkcs12 files
my $bad1 = srctop_file("test", "recipes", "80-test_pkcs12_data", "bad1.p12");
my $bad2 = srctop_file("test", "recipes", "80-test_pkcs12_data", "bad2.p12");
my $bad3 = srctop_file("test", "recipes", "80-test_pkcs12_data", "bad3.p12");

with({ exit_checker => sub { return shift == 1; } },
     sub {
        ok(run(app(["openssl", "pkcs12", "-in", $bad1, "-password", "pass:"])),
           "test bad pkcs12 file 1");

        ok(run(app(["openssl", "pkcs12", "-in", $bad1, "-password", "pass:",
                    "-nomacver"])),
           "test bad pkcs12 file 1 (nomacver)");

        ok(run(app(["openssl", "pkcs12", "-in", $bad1, "-password", "pass:",
                    "-info"])),
           "test bad pkcs12 file 1 (info)");

        ok(run(app(["openssl", "pkcs12", "-in", $bad2, "-password", "pass:"])),
           "test bad pkcs12 file 2");

        ok(run(app(["openssl", "pkcs12", "-in", $bad2, "-password", "pass:",
                    "-info"])),
           "test bad pkcs12 file 2 (info)");

        ok(run(app(["openssl", "pkcs12", "-in", $bad3, "-password", "pass:"])),
           "test bad pkcs12 file 3");

        ok(run(app(["openssl", "pkcs12", "-in", $bad3, "-password", "pass:",
                    "-info"])),
           "test bad pkcs12 file 3 (info)");
     });

SetConsoleOutputCP($savedcp) if (defined($savedcp));
