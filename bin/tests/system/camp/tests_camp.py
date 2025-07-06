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

import re

import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ans*/ans.run",
        "ns*/*.jnl",
        "ns*/*tld*.db",
    ]
)


# helper functions
def grep_q(regex, filename):
    with open(filename, "r", encoding="utf-8") as f:
        blob = f.read().splitlines()
    results = [x for x in blob if re.search(regex, x)]
    return len(results) != 0


def test_max_query_count():
    # check max-query-count is in effect
    msg = isctest.query.create("q.label1.tld1", "a")
    res = isctest.query.tcp(msg, "10.53.0.9")
    isctest.check.servfail(res)
    assert grep_q("exceeded global max queries resolving", "ns9/named.run")
