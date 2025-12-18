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
    try:
        # Sanity test: foo.example exists and is signed.
        msg = isctest.query.create("foo.example", "A", dnssec=True)
        res = isctest.query.tcp(msg, ns4.ip)
        isctest.check.noerror(res)
        isctest.check.adflag(res)
    except:
        dump = ns4.rndc("dumpdb -deleg")
        print(dump)
        exit(1)

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
    assert len(res.authority) == 1

    # ... But the test above also internally cached the authority section
    msg = isctest.query.create("ns3.ghost.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    assert len(res.answer) == 1

    # We're child-centric: the resolver cached the child-side NS record
    # If we haven't done it, we would have the signed answer from ns2 
    # (the delegation point)
    assert res.answer[0].to_text() == "ns3.ghost.example. 555 IN A 10.53.33.33"

    # The explicit query to ns3.ghost.example/A changed the previous trust level
    # (additional) up to authority, which won't enable us to tweak it later, so flush
    # the cache and re-fill it with the additional trust level.
    ns4.rndc("flush")
    msg = isctest.query.create("bar.ghost.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)


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

    # Just in case the non-auth NS would be used to re-trigger some validation
    # or if we had (which we don't) a separate cache DB and a deleg DB, that would
    # make the ghost attack to fail
    time.sleep(10)

    # ... But it works. We can still ask ns4 for anything from ghost.example,
    # even parts which are not cached (baz).
    msg = isctest.query.create("bar.ghost.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    assert len(res.answer) == 1

    msg = isctest.query.create("baz.ghost.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    assert len(res.answer) == 1

    # Let's move a step further: currently ns3.ghost.example/A was added as
    # glue from the referal, so it's trust level is less than authoritative.
    # Let's take this as an advantage to override it now by getting it from the
    # answer section (with is a bigger trust level, so it will override the cache)
    # But before doing that, update it in ns3.
    templates.render(
        "ns3/ghost.example.db",
        {"ns3ttl": 9999, "ns3ip": "10.10.10.10", "extrarr": True},
    )
    with ns3.watch_log_from_here() as watcher:
        ns3.rndc("reload")
        watcher.wait_for_line("running")

    # Now let's query ns3.ghost.example/A. As it's previously cached
    # it won't ask example. NS, thus it will get an authority response
    # wich will even bump its lifetime and change its address.
    msg = isctest.query.create("ns3.ghost.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    assert len(res.answer) == 1

    # We extended the life time of ghost.example. and changed its nameserver address
    assert res.answer[0].to_text() == "ns3.ghost.example. 9999 IN A 10.10.10.10"

    msg = isctest.query.create("gee.ghost.example", "A", dnssec=True)
    res = isctest.query.tcp(msg, ns4.ip)
    isctest.check.noerror(res)
    isctest.check.noadflag(res)
    assert len(res.answer) == 1
    assert res.answer[0].to_text() == "gee.ghost.example. 300 IN A 10.53.0.66"
    assert len(res.authority) == 1
    assert len(res.additional) == 1
    assert res.additional[0].to_text() == "ns3.ghost.example. 9999 IN A 10.10.10.10"
