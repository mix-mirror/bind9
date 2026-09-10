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

import pytest
from dns.rcode import NOERROR, SERVFAIL

import isctest
from isctest.template import NS4, zones
from isctest.zone import Zone, configure_root


def bootstrap():
    zone = Zone("delegsigned", NS4, signed=True)
    zone.configure()
    root = configure_root([zone])

    return {
        "trust_anchors": root.trust_anchors(),
        "zones": zones([root, zone]),
    }


@pytest.mark.parametrize(
    "qname, nsname, rcode",
    [
        ("a.delegonly", "ns10", NOERROR),
        ("a.mixed", "ns10", NOERROR),
        ("a.delegname", "ns10", NOERROR),
        ("a.delegips", "ns10", NOERROR),
        ("a.delegips4", "ns10", NOERROR),
        ("a.delegmultiple", "ns10", NOERROR),
        ("a.delegmandatory", "ns10", NOERROR),
        ("a.delegunsupportedman", "ns2", NOERROR),
        ("a.delegunsupportedman", "ns10", SERVFAIL),
        ("a.delegunsupportedman2", "ns10", NOERROR),
        ("a.delegparam", "ns10", NOERROR),
        ("b.delegparam", "ns10", NOERROR),
        ("a.delegparam2", "ns10", SERVFAIL),
        ("a.delegparam3", "ns10", NOERROR),
    ],
)
def test_deleg_resolver(qname, nsname, rcode, servers):
    msg = isctest.query.create(qname, "A")
    res = isctest.query.udp(msg, servers[nsname].ip)
    isctest.check.rcode(res, rcode)
