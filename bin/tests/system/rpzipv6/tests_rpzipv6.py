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

"""
An IPv6 RPZ rpz-ip trigger for a single isolated zero 16-bit group authored
with the "zz" zero-compression marker is not in canonical form: at query time
ip2name() regenerates the trigger name with a literal ".0" (RFC 5952 forbids
"::" for a single zero group), so a "zz"-spelled name was installed in the
summary tree (with a non-canonical-name warning at load) but never matched.

The resolver now retries the policy-record lookup under the "zz" spelling when
the canonical lookup misses on an IPv6 address, so the rule is enforced
(NXDOMAIN) regardless of which spelling the operator used.  The "double-zero"
control (a length-2 zero run) is canonical and was always enforced.
"""

import pytest

import isctest


@pytest.mark.parametrize(
    "qname",
    [
        # Canonical length-2 zero run.
        "double-zero.lab.",
        # Single isolated zero authored with "zz": honored via the fallback.
        "single-zero.lab.",
        # Single trailing zero authored with "zz": same.
        "trailing-zero.lab.",
    ],
)
def test_rpz_ipv6_single_zero(ns2, qname):
    msg = isctest.query.create(qname, "AAAA")
    res = isctest.query.udp(msg, ns2.ip)
    isctest.check.nxdomain(res)
