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

set -e

. ../conf.sh

DIGOPTS="-p ${PORT}"
RNDCCMD="$RNDC -c ../_common/rndc.conf -p ${CONTROLPORT} -s"

status=0
n=0

n=$((n + 1))
echo_i "test that grease messages are logged (NOERROR) ($n)"
ret=0
$DIG $DIGOPTS example @10.53.0.1 >dig.out.$n || ret=1
grep "status: NOERROR" dig.out.$n >/dev/null || ret=1
p1="grease-dns-flags: 10.53.0.2#[0-9]* example/A: DNS header flag 0x40 not zero"
p2="grease-edns-flags: 10.53.0.2#[0-9]* example/A: Unspecified EDNS flags not zero: 0x[0248]*"
p3="grease-edns-negotiation: 10.53.0.2#[0-9]* example/A: EDNS version negotiation: unexpected rcode: NOERROR"
grep "$p1" ns1/named.run >/dev/null || ret=1
grep "$p2" ns1/named.run >/dev/null || ret=1
grep "$p3" ns1/named.run >/dev/null || ret=1
if [ $ret -eq 1 ]; then
  echo_i "failed"
  status=$((status + 1))
fi

n=$((n + 1))
echo_i "test that grease messages are logged (NXDOMAIN) ($n)"
ret=0
$DIG $DIGOPTS nxdomain.example @10.53.0.1 >dig.out.$n || ret=1
grep "status: NXDOMAIN" dig.out.$n >/dev/null || ret=1
p1="grease-dns-flags: 10.53.0.2#[0-9]* nxdomain.example/A: DNS header flag 0x40 not zero"
p2="grease-edns-flags: 10.53.0.2#[0-9]* nxdomain.example/A: Unspecified EDNS flags not zero: 0x[0248]*"
p3="grease-edns-negotiation: 10.53.0.2#[0-9]* nxdomain.example/A: EDNS version negotiation: unexpected rcode: NXDOMAIN"
grep "$p1" ns1/named.run >/dev/null || ret=1
grep "$p2" ns1/named.run >/dev/null || ret=1
grep "$p3" ns1/named.run >/dev/null || ret=1
if [ $ret -eq 1 ]; then
  echo_i "failed"
  status=$((status + 1))
fi
echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
