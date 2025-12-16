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

import sys

from pathlib import Path

import pytest

# isctest.asyncserver requires dnspython >= 2.0.0
pytest.importorskip("dns", minversion="2.0.0")


def is_el9_with_python_39():
    if sys.version_info[:2] > (3, 9):
        return False
    return 'PLATFORM_ID="platform:el9"' in Path("/etc/os-release").read_text(
        encoding="utf-8"
    )


pytestmark = [
    # ans6 fails on TCP query arrival on EL9 with Python 3.9
    pytest.mark.skipif(
        is_el9_with_python_39(),
        reason="On Enterprise Linux 9, Python > 3.9 is required",
    ),
    pytest.mark.extra_artifacts(
        [
            "awk.out.*",
            "dig.out.*",
            "ns2/example.db",
            "ns2/named-tls.conf",
            "ns2/x21.db*",
            "ns3/example.bk",
            "ns3/named-tls.conf",
            "ns4/named.port",
            "ns4/x21.bk",
            "ns4/x21.bk.jnl",
            "ns5/x21.bk-b",
            "ns5/x21.bk-b.jnl",
            "ns5/x21.bk-c",
            "ns5/x21.bk-c.jnl",
            "ns5/x21.db.jnl",
            "ans6/ans.run",
        ]
    ),
]


def test_notify(run_tests_sh):
    run_tests_sh()
