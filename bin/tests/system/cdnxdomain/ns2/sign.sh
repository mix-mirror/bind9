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

zone=example

ksk=$("$KEYGEN" -q -fk -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")
zsk=$("$KEYGEN" -q -a "$DEFAULT_ALGORITHM" -b "$DEFAULT_BITS" "$zone")

# Sign two versions of the zone with the same keys: one that contains
# "a.example" and one that does not (so a.example yields a signed NXDOMAIN).
# Tests switch between them by copying the wanted variant over the live
# "example.db.signed" file and reloading ns2.
cat example.db.in "$ksk.key" "$zsk.key" >example.db
"$SIGNER" -o "$zone" -f example-full.db.signed example.db >/dev/null

cat example-empty.db.in "$ksk.key" "$zsk.key" >example-empty.db
"$SIGNER" -o "$zone" -f example-empty.db.signed example-empty.db >/dev/null

# The live zone file starts out as the full zone.
cp example-full.db.signed example.db.signed

# Give the resolver (ns1) a static trust anchor for the zone.
keyfile_to_static_ds "$ksk" >../ns1/trusted.conf
