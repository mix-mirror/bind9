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

from dns import reversename, update

import os
import re

import pytest

import isctest

pytestmark = pytest.mark.skipif(bool(os.getenv("TSAN_OPTIONS", "")), reason="TSAN")


# helper functions
def grep_q(regex, filename):
    with open(filename, "r", encoding="utf-8") as f:
        blob = f.read().splitlines()
    results = [x for x in blob if re.search(regex, x)]
    return len(results) != 0


def add(host, rdtype, rdata):
    zone = "ipv4.example.nil." if rdtype == "A" else "ipv6.example.nil."
    up = update.UpdateMessage(zone)
    up.add(host, 300, rdtype, rdata)
    res = isctest.query.tcp(up, "10.53.0.1")
    isctest.check.noerror(res)

    msg = isctest.query.create(host, rdtype)
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert len([str(a) for a in res.answer[0]]) == 1

    rname = str(reversename.from_address(rdata))
    msg = isctest.query.create(rname, "PTR")
    for i in range(10):
        res = isctest.query.tcp(msg, "10.53.0.1")
        if len([str(a) for a in res.answer[0]]) == 1:
            break
        time.sleep(1)
    assert i < 9, f"{rname}/PTR not updated"


def delete(host, rdtype):
    assert rdtype in ("A", "AAAA")

    msg = isctest.query.create(host, rdtype)
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    oldip = str(res.answer[0][0])

    zone = "ipv4.example.nil." if rdtype == "A" else "ipv6.example.nil."
    up = update.UpdateMessage(zone)
    up.delete(host, rdtype)
    res = isctest.query.tcp(up, "10.53.0.1")
    isctest.check.noerror(res)

    msg = isctest.query.create(host, rdtype)
    res = isctest.query.tcp(msg, "10.53.0.1")
    isctest.check.empty_answer(res)

    rname = str(reversename.from_address(oldip))
    msg = isctest.query.create(rname, "PTR")
    for i in range(10):
        res = isctest.query.tcp(msg, "10.53.0.1")
        if not res.answer:
            break
        time.sleep(1)
    assert i < 9, f"{rname}/PTR not deleted"


def test_dyndb_updates():
    add("test1.ipv4.example.nil.", "A", "10.53.0.10")
    add("test2.ipv4.example.nil.", "A", "10.53.0.11")
    add("test3.ipv4.example.nil.", "A", "10.53.0.12")
    add("test4.ipv6.example.nil.", "AAAA", "2001:db8::1")

    delete("test1.ipv4.example.nil.", "A")
    delete("test2.ipv4.example.nil.", "A")
    delete("test3.ipv4.example.nil.", "A")
    delete("test4.ipv6.example.nil.", "AAAA")


def test_dyndb_params():
    # check parameter logging
    assert grep_q(
        "loading params for dyndb 'sample' from .*named.conf:", "ns1/named.run"
    )
    assert grep_q(
        "loading params for dyndb 'sample2' from .*named.conf:", "ns1/named.run"
    )


def test_dyndb_reload(servers):
    # check dyndb still works after reload
    servers["ns1"].rndc("reload", log=False)

    add("test5.ipv4.example.nil.", "A", "10.53.0.10")
    add("test6.ipv6.example.nil.", "AAAA", "2001:db8::1")
    delete("test5.ipv4.example.nil.", "A")
    delete("test6.ipv6.example.nil.", "AAAA")
