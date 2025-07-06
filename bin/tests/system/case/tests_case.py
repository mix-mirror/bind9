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

from dns import update

import time

import pytest

import isctest


pytestmark = pytest.mark.extra_artifacts(
    [
        "ns1/dynamic.db",
        "ns1/dynamic.db.jnl",
        "ns2/dynamic.bk",
        "ns2/dynamic.bk.jnl",
        "ns2/example.bk",
    ]
)


def readfile(filename):
    # this reads a file and normalizes all the whitespace
    with open(filename, "r", encoding="utf-8") as f:
        return [" ".join(a.split()) for a in f.read().splitlines()]


def wait_for_serial(qname, serial):
    msg = isctest.query.create(qname, "soa")
    for _ in range(20):
        res = isctest.query.tcp(msg, "10.53.0.2")
        soa = res.answer[0]
        if soa[0].serial == serial:
            return True
        time.sleep(1)
    return False


def test_init():
    assert wait_for_serial("example", 2000042407)
    assert wait_for_serial("dynamic", 2000042407)


def test_case_preservation():
    # no ACL
    msg = isctest.query.create("example", "mx")
    res = isctest.query.tcp(msg, "10.53.0.1")
    mxset = res.answer[0]
    assert "0 mail.eXaMpLe" in str(mxset[0])
    assert "mAiL.example." in [str(a.name) for a in res.additional]

    # no-case-compress ACL { 10.53.0.2 } - non-matching query, then matching
    res = isctest.query.tcp(msg, "10.53.0.1", source="10.53.0.1")
    assert "0 mail.eXaMpLe" in str(mxset[0])
    assert "mAiL.example." in [str(a.name) for a in res.additional]
    mxset = res.answer[0]

    res = isctest.query.tcp(msg, "10.53.0.2", source="10.53.0.2")
    mxset = res.answer[0]
    assert "0 mail.example" in str(mxset[0])
    assert "mail.example." in [str(a.name) for a in res.additional]


def test_case_loadxfer():
    # ns1 loads a dynamic zone with variously-cased $ORIGIN values
    msg = isctest.query.create("dynamic", "axfr")
    res = isctest.query.tcp(msg, "10.53.0.1")

    expected = readfile("dynamic.good")
    isctest.log.debug("EXP:" + str(expected))

    # this splits the RRsets and creates a list of individual RRs
    records = sum([str(a).splitlines() for a in res.answer], [])
    isctest.log.debug("GOT: " + str(records))

    # check for equivalence
    assert set(records) == set(expected)

    # ns2 transfers the zone
    res = isctest.query.tcp(msg, "10.53.0.1")
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert set(records) == set(expected)


def test_case_update():
    # change SOA owner case via update
    up = update.UpdateMessage("dYNAMIc.")
    up.add("dYNAMIc.", 300, "SOA", "mname1. . 2000042408 20 20 1814400 3600")
    res = isctest.query.tcp(up, "10.53.0.1")
    isctest.check.noerror(res)

    expected = readfile("postupdate.good")

    msg = isctest.query.create("dynamic", "axfr")
    res = isctest.query.tcp(msg, "10.53.0.1")
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert set(records) == set(expected)

    assert wait_for_serial("dynamic", 2000042408)
    res = isctest.query.tcp(msg, "10.53.0.2")
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert set(records) == set(expected)

    up = update.UpdateMessage("DyNaMIC.")
    up.add("Ns1.DyNaMIC.", 300, "A", "10.53.0.1")
    res = isctest.query.tcp(up, "10.53.0.1")
    isctest.check.noerror(res)

    expected = readfile("postns1.good")
    res = isctest.query.tcp(msg, "10.53.0.1")
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert set(records) == set(expected)

    assert wait_for_serial("dynamic", 2000042409)
    res = isctest.query.tcp(msg, "10.53.0.2")
    records = sum([str(a).splitlines() for a in res.answer], [])
    assert set(records) == set(expected)
