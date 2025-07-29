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

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ns*/*.db",
        "ns*/*.signed",
        "ns*/dsset-*",
        "ns*/K*.key",
        "ns*/K*.private",
        "ns*/managed.conf",
        "ns*/trusted.conf",
        "ns5/named_dump*",
    ]
)


def get_sfcache():
    dump = []
    log = False
    for line in open("ns5/named_dump.db", encoding="utf-8"):
        line = line.strip()
        if "SERVFAIL" in line:
            log = True
        elif "Zone" in line:
            log = False
        elif log and line != ";":
            dump += [line]
    return dump


def test_servfail_cache_dnssec(ns5):
    # check DNSSEC servfail is cached
    msg = isctest.query.create("foo.example", "a")
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)
    ns5.rndc("dumpdb -all", log=False)

    assert any("foo.example/A" in a for a in get_sfcache())

    # re-query and check SERVFAIL is returned from the cache
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)

    # check that CD bypasses the cache check
    msg = isctest.query.create("foo.example", "a", cd=True)
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.noerror(res)


def test_servfail_cache_non_dnssec(ns5):
    # flush and confirm there's nothing in the SERVFAIL cache
    ns5.rndc("flush", log=False)
    ns5.rndc("dumpdb -all", log=False)
    assert len(get_sfcache()) == 0

    # check SERVFAIL is cached
    msg = isctest.query.create("bar.example2", "a")
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)

    ns5.rndc("dumpdb -all", log=False)
    assert any("bar.example2/A" in a for a in get_sfcache())

    # check that CD bypasses the cache check
    msg = isctest.query.create("bar.example2", "a", cd=True)
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)
    ns5.log.prohibit("servfail cache hit bar.example2/A")

    # re-query and check SERVFAIL is returned from the cache
    res = isctest.query.tcp(msg, "10.53.0.5")
    isctest.check.servfail(res)
    ns5.log.expect("servfail cache hit bar.example2/A")
