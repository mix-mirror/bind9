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

from re import compile as Re

import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ns2/named_dump.db",
    ]
)


def dump_cache(ns2):
    with ns2.watch_log_from_here() as watcher:
        ns2.rndc("dumpdb -cache _default")
        watcher.wait_for_line("dumpdb complete")
    return isctest.text.TextFile("ns2/named_dump.db")


def test_flushname_root(ns2):
    # prime the cache
    msg = isctest.query.create("top1.flushtest.example.", "TXT")
    res = isctest.query.udp(msg, ns2.ip)
    isctest.check.noerror(res)
    assert dump_cache(ns2).grep(Re(r"top1\.flushtest\.example"))

    # "rndc flushname ." flushes the root node only, not the whole cache
    with ns2.watch_log_from_here() as watcher:
        ns2.rndc("flushname .")
        watcher.wait_for_line("flushing name '.' in DNS cache for all views succeeded")
    assert dump_cache(ns2).grep(Re(r"top1\.flushtest\.example"))

    # "rndc flushtree ." empties the entire cache
    with ns2.watch_log_from_here() as watcher:
        ns2.rndc("flushtree .")
        watcher.wait_for_line("flushing tree '.' in DNS cache for all views succeeded")
    assert not dump_cache(ns2).grep(Re(r"flushtest\.example"))
