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
. ../conf.sh

set -e

copy_setports ns2/multisigner.db.in ns2/multisigner.db.infile
copy_setports ns2/secondary.db.in ns2/secondary.db.infile

# multi-signers
(
  cd ns3
  $SHELL setup.sh
)
(
  cd ns4
  $SHELL setup.sh
)
(
  cd ns5
  $SHELL setup.sh
)
# tld
(
  cd ns2
  $SHELL setup.sh
)
# root
(
  cd ns1
  $SHELL setup.sh
)
