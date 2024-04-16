#!/usr/bin/env bash

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

set -eou pipefail

if [ -z "$MESON_SOURCE_ROOT" ] || [ -z "$MESON_BUILD_ROOT" ]; then
    echo "system-test-scope.sh must be run within meson!"
    exit 1
fi

for file in $MESON_BUILD_ROOT/bin/tests/system/isctest/vars/.ac_vars/*; do
    cp $file $MESON_SOURCE_ROOT/bin/tests/system/isctest/vars/.ac_vars/${file##*/}
done
