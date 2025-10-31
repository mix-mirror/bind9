#!/bin/sh

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

. ../conf.sh

dnspython_genzone() (
  servers="$@"
  # Drop unusual RR sets and RR types (AMTRELAY, GPOS, URI, apl02) dnspython
  # can't handle. For more information see
  # https://github.com/rthalley/dnspython/issues/1034#issuecomment-1896541899.
  # - BRID and HHIT are not supported by dnspython at all.
  # - dnspython v2.8.0 adds support for DSYNC RR type
  # - dnspython v2.7.0 adds support for RESINFO and WALLET RR types
  $SHELL "${TOP_SRCDIR}/bin/tests/system/genzone.sh" $servers \
    | sed \
      -e '/AMTRELAY.*\# 2 0004/d' \
      -e '/BRID/d' \
      -e '/DSYNC/d' \
      -e '/GPOS.*"" "" ""/d' \
      -e '/HHIT/d' \
      -e '/RESINFO/d' \
      -e '/URI.*30 40 ""/d' \
      -e '/WALLET/d' \
      -e '/apl02/d' \
    | tr "\t" " "
)

dnspython_genzone 1 6 7 >ns1/sec.db
dnspython_genzone 1 6 7 >ns1/edns-expire.db
dnspython_genzone 2 3 >ns2/example.db
dnspython_genzone 2 3 >ns2/tsigzone.db
dnspython_genzone 6 3 >ns6/primary.db
dnspython_genzone 7 >ns7/primary2.db

cp -f ns4/root.db.in ns4/root.db
$PERL -e 'for ($i=0;$i<10000;$i++){ printf("x%u 0 in a 10.53.0.1\n", $i);}' >>ns4/root.db

copy_setports ns2/named.conf.in ns2/named.conf
copy_setports ns3/named.conf.in ns3/named.conf
copy_setports ns6/named.conf.in ns6/named.conf
copy_setports ns7/named.conf.in ns7/named.conf
copy_setports ns8/named.conf.in ns8/named.conf

copy_setports ns4/named.conf.base.in ns4/named.conf

cp ns1/dot-fallback.db.in ns1/dot-fallback.db

cp ns2/sec.db.in ns2/sec.db
touch -t 200101010000 ns2/sec.db

cp ns2/mapped.db.in ns2/mapped.db

$PERL -e 'for ($i=0;$i<4096;$i++){ printf("name%u 259200 A 1.2.3.4\nname%u 259200 TXT \"Hello World %u\"\n", $i, $i, $i);}' >ns8/small.db
$PERL -e 'printf("large IN TYPE45234 \\# 48000 "); for ($i=0;$i<16*3000;$i++) { printf("%02x", $i % 256); } printf("\n");' >ns8/large.db

cp -f ns1/ixfr-too-big.db.in ns1/ixfr-too-big.db
