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

import re

import isctest


# helper functions
def grep_q(regex, filename):
    with open(filename, "r", encoding="utf-8") as f:
        blob = f.read().splitlines()
    results = [x for x in blob if re.search(regex, x)]
    return len(results) != 0


def test_integrity():
    # check 'check-integrity yes; check-mx-cname fail;'
    msg = isctest.query.create("mx-cname-fail", "mx")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.servfail(res)
    assert grep_q(
        "zone mx-cname-fail/IN: mx-cname-fail/MX 'cname.mx-cname-fail' is a CNAME",
        "ns1/named.run"
    )

    # check 'check-integrity yes; check-mx-cname warn;'
    msg = isctest.query.create("mx-cname-warn", "mx")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert grep_q(
        "zone mx-cname-warn/IN: mx-cname-warn/MX 'cname.mx-cname-warn' is a CNAME",
        "ns1/named.run"
    )

    # check 'check-integrity yes; check-mx-cname ignore;'
    msg = isctest.query.create("mx-cname-ignore", "mx")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert not grep_q(
        "zone mx-cname-ignore/IN: mx-cname-ignore/MX 'cname.mx-cname-ignore' is a CNAME",
        "ns1/named.run"
    )

    # check 'check-integrity no; check-mx-cname fail;'
    msg = isctest.query.create("no-mx-cname-fail", "mx")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert not grep_q(
        "zone no-mx-cname-fail/IN: no-mx-cname-fail/MX 'cname.no-mx-cname-fail' is a CNAME",
        "ns1/named.run"
    )

    # check 'check-integrity no; check-mx-cname warn;'
    msg = isctest.query.create("no-mx-cname-warn", "mx")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert not grep_q(
        "zone no-mx-cname-warn/IN: no-mx-cname-warn/MX 'cname.no-mx-cname-warn' is a CNAME",
        "ns1/named.run"
    )

    # check 'check-integrity no; check-mx-cname ignore;'
    msg = isctest.query.create("no-mx-cname-ignore", "mx")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert not grep_q(
        "zone no-mx-cname-ignore/IN: no-mx-cname-ignore/MX 'cname.no-mx-cname-ignore' is a CNAME",
        "ns1/named.run"
    )

    # check 'check-integrity yes; check-srv-cname fail;'
    msg = isctest.query.create("srv-cname-fail", "srv")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.servfail(res)
    assert grep_q(
        "zone srv-cname-fail/IN: srv-cname-fail/SRV 'cname.srv-cname-fail' is a CNAME",
        "ns1/named.run"
    )

    # check 'check-integrity yes; check-srv-cname warn;'
    msg = isctest.query.create("srv-cname-warn", "srv")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert grep_q(
        "zone srv-cname-warn/IN: srv-cname-warn/SRV 'cname.srv-cname-warn' is a CNAME",
        "ns1/named.run"
    )

    # check 'check-integrity yes; check-srv-cname ignore;'
    msg = isctest.query.create("srv-cname-ignore", "srv")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert not grep_q(
        "zone srv-cname-ignore/IN: srv-cname-ignore/SRV 'cname.srv-cname-ignore' is a CNAME",
        "ns1/named.run"
    )

    # check 'check-integrity no; check-srv-cname fail;'
    msg = isctest.query.create("no-srv-cname-fail", "srv")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert not grep_q(
        "zone no-srv-cname-fail/IN: no-srv-cname-fail/SRV 'cname.no-srv-cname-fail' is a CNAME",
        "ns1/named.run"
    )

    # check 'check-integrity no; check-srv-cname warn;'
    msg = isctest.query.create("no-srv-cname-warn", "srv")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert not grep_q(
        "zone no-srv-cname-warn/IN: no-srv-cname-warn/SRV 'cname.no-srv-cname-warn' is a CNAME",
        "ns1/named.run"
    )

    # check 'check-integrity no; check-srv-cname ignore;'
    msg = isctest.query.create("no-srv-cname-ignore", "srv")
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert not grep_q(
        "zone no-srv-cname-ignore/IN: no-srv-cname-ignore/SRV 'cname.no-srv-cname-ignore' is a CNAME",
        "ns1/named.run"
    )
