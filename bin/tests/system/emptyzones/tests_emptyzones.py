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

import isctest


def test_emptyzones(ns1, templates):
    # check that switching to automatic empty zones works
    templates.render("ns1/named.conf", {"automatic_empty_zones": True})
    ns1.reconfigure(log=False)
    msg = isctest.query.create("version.bind", "TXT", "CH")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)

    # check that allow-transfer { none; } works
    msg = isctest.query.create("10.in-addr.arpa", "AXFR")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.refused(res)

    # check that disabling 127.in-addr.arpa works
    msg = isctest.query.create("1.0.0.127.in-addr.arpa", "PTR")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    msg = isctest.query.create("127.127.127.127.in-addr.arpa", "PTR")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.servfail(res)

    # switch to rfc1918.zones configuration
    templates.render("ns1/named.conf", {"automatic_empty_zones": False})
    ns1.reconfigure(log=False)

    # check that empty.db works
    msg = isctest.query.create("1.0.53.10.in-addr.arpa", "PTR")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.nxdomain(res)
