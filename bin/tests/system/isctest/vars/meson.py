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

import os

from typing import Dict


def load_vars_from_env() -> Dict[str, str]:
    var_targets = [
        "TOP_BUILDDIR",
        "SHELL",
        "PERL",
        "XSLTPROC",
        "CURL",
        "NC",
        "TOP_SRCDIR",
        "FSTRM_CAPTURE",
        "PYTEST",
        "PYTHON",
    ]

    return {k: v for k in var_targets if (v := os.getenv(k)) is not None}


MESON_VARS = load_vars_from_env()
