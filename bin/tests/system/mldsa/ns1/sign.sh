#!/bin/sh -e

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

. ../../conf.sh

zone=.
infile=root.db.in
zonefile=root.db

echo_i "ns1/sign.sh"

cp "$infile" "$zonefile"

zsk=$($KEYGEN -q -a ML-DSA-44 "$zone")
ksk=$($KEYGEN -q -a ML-DSA-44 -f KSK "$zone")

cat "$ksk.key" "$zsk.key" >>"$zonefile"
$DSFROMKEY -a sha-256 "$ksk.key" >>dsset-256

# Configure the resolving server with a static key.
keyfile_to_static_ds "$ksk" >trusted.conf
cp trusted.conf ../ns2/trusted.conf

$SIGNER -P -g -o "$zone" "$zonefile" >/dev/null 2>signer.err || cat signer.err
