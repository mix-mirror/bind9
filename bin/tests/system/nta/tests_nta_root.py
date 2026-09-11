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


def test_nta_root(ns4):
    # prime the cache with an answer that validates
    msg = isctest.query.create("a.secure.example.", "A")
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    # adding a root NTA must not crash named, and must flush the cache
    # so that the answer cached as secure is re-resolved without
    # validation
    response = ns4.rndc("nta -f -l 60s .")
    assert "Negative trust anchor added: ./_default" in response.out

    response = ns4.rndc("nta -d")
    assert "./_default: expiry" in response.out

    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.noadflag(res)

    # removing the root NTA must not crash named either, and must flush
    # the cache again so that validation resumes immediately
    response = ns4.rndc("nta -remove .")
    assert "Negative trust anchor removed: ./_default" in response.out

    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.adflag(res)
