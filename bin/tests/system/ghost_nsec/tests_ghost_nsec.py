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

import os
import time
import re

import isctest


def test_ghost_nsec(ns2, ns3, ns4, templates):
    # Sanity test: foo.example exists and is signed.
    msg = isctest.query.create("foo.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.adflag(res)

    # Sanity test: non existance proof works and is signed.
    msg = isctest.query.create("idonotexists", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.nxdomain(res)
    isctest.check.adflag(res)

    # Sanity test: bar.ghost.example exists and is not signed.
    msg = isctest.query.create("bar.ghost.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    assert len(res.answer) == 1

    # Also fetch the NS/A of the ns3 in the child-side of the zonecut.
    # Those ones have a way bigger TTL
    msg = isctest.query.create("ns3.ghost.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    assert len(res.answer) == 1
    assert res.answer[0].to_text() == "ns3.ghost.example. 300 IN A 10.53.0.3"
    msg = isctest.query.create("ghost.example", "NS", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    assert len(res.answer) == 1
    assert res.answer[0].to_text() == "ghost.example. 300 IN NS ns3.ghost.example."

    # Now let's remove the delegation
    templates.render("ns2/example.db.in", {"ghost": False})
    os.chdir("ns2")
    isctest.run.shell("sign.sh")
    os.chdir("..")
    with ns2.watch_log_from_here() as watcher:
        ns2.rndc("reload")
        watcher.wait_for_line("running")

    # Call ns2 directly to see there is no ghost child anymore
    msg = isctest.query.create("ns3.ghost.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns2.ip)
    isctest.check.nxdomain(res)

    # The parent-side delegation will expire (5 seconds). 
    time.sleep(10)

    # bar.ghost.example is cached in the main DB and has a longer expiration,
    # so it is still there.
    msg = isctest.query.create("bar.ghost.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    assert len(res.answer) == 1

    # But another name (which exists in the child) is not reachable anymore,
    # since the delegation has expired (and we didn't used the child-side
    # of the delegation for the delegdb when we explicitly fetch it above).
    msg = isctest.query.create("baz.ghost.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.nxdomain(res)
    isctest.check.noadflag(res)
