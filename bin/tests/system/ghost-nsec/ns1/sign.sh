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

# shellcheck source=conf.sh
. ../../conf.sh

set -e

echo_i "ns1/sign.sh"

# Sign the root zone
zone=.
infile=root.db.in
zonefile=root.db
ksk=$("$KEYGEN" -q -fk -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
zsk=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
cat "$infile" "$ksk.key" "$zsk.key" >"$zonefile"
"$SIGNER" -g -o "$zone" "$zonefile" >/dev/null 2>&1

# Copy the (fake) root trust anchors to the resolver
keyfile_to_static_ds "$ksk" >trusted.conf
cp trusted.conf ../ns4/trusted.conf
