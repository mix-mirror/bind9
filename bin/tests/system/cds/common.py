# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import pytest

EXTRA_ARTIFACTS = pytest.mark.extra_artifacts(
    [
        "CDNSKEY.*",
        "CDS.*",
        "DS.*",
        "K*",
        "UP.*",
        "brk.*",
        "child_file.*",
        "db.*",
        "empty",
        "err.*",
        "out.*",
        "sig.*",
        "vars.sh",
        "xerr",
        "xout",
        "t*/dsset-*",
        "t*/example.test.*",
        "t*/K*",
    ]
)
