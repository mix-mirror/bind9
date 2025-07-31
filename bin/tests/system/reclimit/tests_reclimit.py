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

import time

from dns import name, rdatatype

import pytest

import isctest


pytestmark = pytest.mark.extra_artifacts(
    [
        "dsset-signed.",
        "ans*/ans.limit",
        "ans*/ans.run",
        "ns1/K*",
        "ns1/signed.db",
        "ns1/signed.db.signed",
    ]
)


def getcount(addr):
    msg = isctest.query.create("count", "txt")
    res = isctest.query.udp(msg, addr)
    return int(str(res.answer[0][0]).strip('"'))


def test_maxrecdepth12(ns3, templates):
    # set max-recursion-depth to 12
    templates.render("ns3/named.conf", {"recursiondepth": 12})
    ns3.reconfigure(log=False)

    # reset the ANS limits
    templates.render("ans2/ans.limit", {"limit": 1000})
    templates.render("ans4/ans.limit", {"limit": 1000})
    msg = isctest.query.create("reset", "a")
    isctest.query.udp(msg, "10.53.0.2")
    isctest.query.udp(msg, "10.53.0.4")

    # send excessive-depth query
    msg = isctest.query.create("indirect1.example.org", "a")
    res = isctest.query.udp(msg, "10.53.0.3")
    isctest.check.servfail(res)

    # check query counts from ANS
    use_aaaa = "started AAAA fetch" in ns3.log
    expected = 27 if use_aaaa else 14
    total = getcount("10.53.0.2") + getcount("10.53.0.4")
    assert total == expected

    # reset ANS limits
    templates.render("ans2/ans.limit", {"limit": 12})
    templates.render("ans4/ans.limit", {"limit": 12})
    msg = isctest.query.create("reset", "a")
    isctest.query.udp(msg, "10.53.0.2")
    isctest.query.udp(msg, "10.53.0.4")
    ns3.rndc("flush", log=False)

    # send permissible query
    msg = isctest.query.create("indirect2.example.org", "a")
    res = isctest.query.udp(msg, "10.53.0.3")
    isctest.check.noerror(res)

    # check query counts
    expected = 50 if use_aaaa else 26
    total = getcount("10.53.0.2") + getcount("10.53.0.4")
    assert total == expected


def test_maxrecdepth5(ns3, templates):
    # set max-recursion-depth to 5
    templates.render("ns3/named.conf", {"recursiondepth": 5})
    ns3.reconfigure(log=False)
    ns3.rndc("flush", log=False)

    # reset the ANS limits
    templates.render("ans2/ans.limit", {"limit": 12})
    templates.render("ans4/ans.limit", {"limit": 12})
    msg = isctest.query.create("reset", "a")
    isctest.query.udp(msg, "10.53.0.2")
    isctest.query.udp(msg, "10.53.0.4")

    # send excessive-depth lookup
    msg = isctest.query.create("indirect3.example.org", "a")
    res = isctest.query.udp(msg, "10.53.0.3")
    isctest.check.servfail(res)

    # check query counts from ANS
    use_aaaa = "started AAAA fetch" in ns3.log
    expected = 13 if use_aaaa else 7
    total = getcount("10.53.0.2") + getcount("10.53.0.4")
    assert total == expected

    # reset the ANS limits
    templates.render("ans2/ans.limit", {"limit": 5})
    templates.render("ans4/ans.limit", {"limit": 5})
    msg = isctest.query.create("reset", "a")
    isctest.query.udp(msg, "10.53.0.2")
    isctest.query.udp(msg, "10.53.0.4")
    ns3.rndc("flush", log=False)

    # send permissible lookup
    msg = isctest.query.create("indirect4.example.org", "a")
    res = isctest.query.udp(msg, "10.53.0.3")
    isctest.check.noerror(res)

    # check query counts from ANS
    expected = 22 if use_aaaa else 12
    total = getcount("10.53.0.2") + getcount("10.53.0.4")
    assert total == expected


def test_maxqueries50(ns3, templates):
    # set max-recursion-depth to 100; max-recursion-queries defaults to 50.
    templates.render("ns3/named.conf", {"recursiondepth": 100})
    ns3.reconfigure(log=False)
    ns3.rndc("flush", log=False)

    # reset the ANS limits
    templates.render("ans2/ans.limit", {"limit": 13})
    # templates.render("ans4/ans.limit", {"limit": 13})
    msg = isctest.query.create("reset", "a")
    isctest.query.udp(msg, "10.53.0.2")
    # isctest.query.udp(msg, "10.53.0.4")

    # send excessive-depth lookup
    msg = isctest.query.create("indirect5.example.org", "a")
    res = isctest.query.udp(msg, "10.53.0.3")
    isctest.check.servfail(res)

    # check query counts from ANS
    assert getcount("10.53.0.2") <= 50

    # reset the ANS limits
    templates.render("ans2/ans.limit", {"limit": 12})
    # templates.render("ans4/ans.limit", {"limit": 12})
    msg = isctest.query.create("reset", "a")
    isctest.query.udp(msg, "10.53.0.2")
    # isctest.query.udp(msg, "10.53.0.4")
    ns3.rndc("flush", log=False)

    # send permissible lookup
    msg = isctest.query.create("indirect6.example.org", "a")
    res = isctest.query.udp(msg, "10.53.0.3")
    isctest.check.noerror(res)

    # check query counts from ANS
    assert getcount("10.53.0.2") <= 50


def test_maxqueries40(ns3, templates):
    # set max-recursion-depth to 100, max-recursion-queries to 40
    templates.render("ns3/named.conf", {"recursiondepth": 100, "recursionqueries": 40})
    ns3.reconfigure(log=False)
    ns3.rndc("flush", log=False)

    # reset the ANS limits
    templates.render("ans2/ans.limit", {"limit": 11})
    msg = isctest.query.create("reset", "a")
    isctest.query.udp(msg, "10.53.0.2")

    # send excessive-depth lookup
    msg = isctest.query.create("indirect7.example.org", "a")
    res = isctest.query.udp(msg, "10.53.0.3")
    isctest.check.servfail(res)

    # check query counts from ANS
    assert getcount("10.53.0.2") <= 40

    # reset the ANS limits
    templates.render("ans2/ans.limit", {"limit": 9})
    msg = isctest.query.create("reset", "a")
    isctest.query.udp(msg, "10.53.0.2")
    ns3.rndc("flush", log=False)

    # send permissible lookup
    msg = isctest.query.create("indirect8.example.org", "a")
    res = isctest.query.udp(msg, "10.53.0.3")
    isctest.check.noerror(res)

    # check query counts from ANS
    assert getcount("10.53.0.2") <= 40


def test_ns_explosion(ns3, templates):
    # set max-recursion-depth to 100, max-recursion-queries to 40
    templates.render("ns3/named.conf", {"recursiondepth": 100, "recursionqueries": 40})
    ns3.reconfigure(log=False)
    ns3.rndc("flush", log=False)

    # reset ANS limits
    templates.render("ans2/ans.limit", {"limit": 11})
    msg = isctest.query.create("reset", "a")
    isctest.query.udp(msg, "10.53.0.2")

    # send exploding query
    msg = isctest.query.create("ns1.1.example.net", "a")
    res = isctest.query.udp(msg, "10.53.0.3")

    # check query counts from ANS
    assert getcount("10.53.0.2") <= 50
    assert getcount("10.53.0.7") <= 50


@pytest.mark.flaky(max_runs=2)
def test_typespername(ns3, templates):
    def check_manytypes(qname, qtype, exname, extype, ttl, exfound):
        msg = isctest.query.create(qname, qtype)
        res = isctest.query.udp(msg, "10.53.0.3")
        isctest.check.noerror(res)
        found = False
        for rrset in res.answer + res.authority + res.additional:
            if rrset.name != name.from_text(exname):
                continue
            if rrset.rdtype != rdatatype.from_text(extype):
                continue
            if rrset.ttl != ttl:
                continue
            found = True
            break
        assert found == exfound, str(rrset)

    # check that too many types cause a failure
    with ns3.watch_log_from_here() as watcher:
        msg = isctest.query.create("biganswer.big", "a")
        res = isctest.query.udp(msg, "10.53.0.3")
        isctest.check.servfail(res)
        watcher.wait_for_line("'biganswer.big/A' in './IN' (cache): too many records")

    # lift the limit and try again
    templates.render("ns3/named.conf", {"recordspertype": 0, "typespername": 10})
    ns3.reconfigure(log=False)
    ns3.rndc("flush", log=False)

    msg = isctest.query.create("biganswer.big", "a")
    res = isctest.query.udp(msg, "10.53.0.3")
    isctest.check.noerror(res)

    # check priority types are cached
    for qtype in ("aaaa", "mx", "ns"):
        check_manytypes("manytypes.big", qtype, "big", "soa", 120, True)
    time.sleep(1)
    for qtype in ("aaaa", "mx", "ns"):
        check_manytypes("manytypes.big", qtype, "big", "soa", 120, False)

    # check caching of types under the max-types-per-name limit
    ns3.rndc("flush", log=False)

    for qtype in range(65270, 65280):
        check_manytypes("manytypes.big", f"TYPE{qtype}", "big", "soa", 120, True)
    time.sleep(1)
    for qtype in range(65270, 65280):
        check_manytypes("manytypes.big", f"TYPE{qtype}", "big", "soa", 120, False)

    # next ten types should be cached and the previous ones evicted.
    for qtype in range(65280, 65290):
        check_manytypes(
            "manytypes.big", f"TYPE{qtype}", "manytypes.big", f"TYPE{qtype}", 120, True
        )
    time.sleep(1)
    for qtype in range(65280, 65290):
        check_manytypes(
            "manytypes.big", f"TYPE{qtype}", "manytypes.big", f"TYPE{qtype}", 120, False
        )

    # check that the previous ones have been evicted
    for qtype in range(65270, 65280):
        check_manytypes("manytypes.big", f"TYPE{qtype}", "big", "soa", 0, True)

    # try priority types again
    for qtype in ("aaaa", "mx", "ns"):
        check_manytypes("manytypes.big", qtype, "big", "soa", 120, True)
    time.sleep(1)
    for qtype in ("aaaa", "mx", "ns"):
        check_manytypes("manytypes.big", qtype, "big", "soa", 120, False)

    # this was the first non-priority type cached, so should be evicted now
    check_manytypes(
        "manytypes.big", f"TYPE65280", "manytypes.big", f"TYPE65280", 120, True
    )

    # check that priority types over the limit aren't evicted
    ns3.rndc("flush", log=False)
    check_manytypes("manytypes.big", "a", "manytypes.big", "a", 120, True)
    time.sleep(1)
    check_manytypes("manytypes.big", "a", "manytypes.big", "a", 120, False)

    for qtype in range(65280, 65290):
        check_manytypes(
            "manytypes.big", f"TYPE{qtype}", "manytypes.big", f"TYPE{qtype}", 120, True
        )

    # priority name should still be cached
    check_manytypes("manytypes.big", "a", "manytypes.big", "a", 120, False)

    # check non-priority types cause eviction
    for qtype in range(65280, 65300):
        # look up 20 types
        check_manytypes(
            "manytypes.big", f"TYPE{qtype}", "manytypes.big", f"TYPE{qtype}", 120, True
        )
    time.sleep(1)
    for qtype in range(65291, 65300):
        # the most recent nine should now have TTL < 120
        check_manytypes(
            "manytypes.big", f"TYPE{qtype}", "manytypes.big", f"TYPE{qtype}", 120, False
        )
    for qtype in range(65280, 65291):
        # and the rest should be TTL 120 again because they were evicted
        check_manytypes(
            "manytypes.big", f"TYPE{qtype}", "manytypes.big", f"TYPE{qtype}", 120, True
        )
    for qtype in range(65291, 65300):
        # ... and now these should be TTL 120, because of the previous block
        check_manytypes(
            "manytypes.big", f"TYPE{qtype}", "manytypes.big", f"TYPE{qtype}", 120, True
        )

    # the priority type should still be here
    check_manytypes("manytypes.big", "a", "manytypes.big", "a", 120, False)

    # check signed names under the types-per-name limit are cached
    ns3.rndc("flush", log=False)

    # 10 queries should result in 20 records (type + rrsig)
    for qtype in range(65280, 65290):
        check_manytypes(
            "manytypes.signed",
            f"TYPE{qtype}",
            "manytypes.signed",
            f"TYPE{qtype}",
            120,
            True,
        )
    time.sleep(1)
    for qtype in range(65285, 65290):
        # the most recent five should now have TTL < 120
        check_manytypes(
            "manytypes.signed",
            f"TYPE{qtype}",
            "manytypes.signed",
            f"TYPE{qtype}",
            120,
            False,
        )
    for qtype in range(65280, 65285):
        # and the rest should be TTL 120 again because they were evicted
        check_manytypes(
            "manytypes.signed",
            f"TYPE{qtype}",
            "manytypes.signed",
            f"TYPE{qtype}",
            120,
            True,
        )
    for qtype in range(65285, 65290):
        # ... and now these should be TTL 120, because of the previous block
        check_manytypes(
            "manytypes.signed",
            f"TYPE{qtype}",
            "manytypes.signed",
            f"TYPE{qtype}",
            120,
            True,
        )

    # check that lifting the limit allows everything to be cached
    templates.render("ns3/named.conf", {"recordspertype": 0, "typespername": 0})
    ns3.reconfigure(log=False)
    ns3.rndc("flush", log=False)

    for qtype in range(65280, 65534):
        # send a few hundred qtypes...
        check_manytypes("manytypes.big", f"TYPE{qtype}", "manytypes.big", f"TYPE{qtype}", 120, True)
    time.sleep(1)
    for qtype in range(65280, 65534):
        # and all should be cached
        check_manytypes("manytypes.big", f"TYPE{qtype}", "manytypes.big", f"TYPE{qtype}", 120, False)
