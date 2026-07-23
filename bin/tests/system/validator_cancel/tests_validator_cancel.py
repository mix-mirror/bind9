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

from isctest.template import NS1, NS2, NS3, Nameserver, zones
from isctest.zone import Zone

import isctest

ANS4 = Nameserver("ans4")


def bootstrap():
    hoster1 = Zone("hoster1.", NS2, signed=True)
    hoster1.configure()

    hoster2 = Zone("hoster2.", ANS4, signed=True)
    hoster2.configure()

    tld = Zone("tld.", NS3, signed=True)
    tld.configure()

    root = Zone(".", NS1, signed=True)
    root.delegations = [hoster1, hoster2, tld]
    root.configure()

    return {
        "trust_anchors": root.trust_anchors(),
        "zones": zones([root, hoster1, hoster2, tld]),
    }


def test_validator_cancel(ns5):
    query = isctest.query.create("foo.tld", "A")
    with ns5.watch_log_from_here() as watcher:
        res = isctest.query.udp(query, ns5.ip)
        isctest.check.noerror(res)
        isctest.check.adflag(res)
        ns5.rndc("stop")
        watcher.wait_for_line("no longer listening on")
    assert "broken trust chain resolving" not in ns5.log
