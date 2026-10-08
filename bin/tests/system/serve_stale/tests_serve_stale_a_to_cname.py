# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

"""
When a name changes from an A RRset to a CNAME, the CNAME cached by the stale
refresh supersedes the stale A: once the CNAME goes stale as well, it is the
CNAME which has to be served, not the A it replaced.
"""

from re import compile as Re

import time

import dns.edns
import dns.message
import dns.rrset
import dns.update
import pytest

from isctest.instance import NamedInstance
from isctest.template import TemplateEngine

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "ns*/named_dump.db",
        "ns*/root.bk",
        "ns1/stale.test.db.jnl",
    ]
)

QNAME = "a-to-cname.stale.test."
OLD_A = dns.rrset.from_text(QNAME, 1, "IN", "A", "192.0.0.2")
NEW_CNAME = dns.rrset.from_text(QNAME, 1, "IN", "CNAME", "a2.stale.test.")


@pytest.fixture(scope="module", autouse=True)
def after_servers_start(
    ns1: NamedInstance, ns3: NamedInstance, templates: TemplateEngine
) -> None:
    templates.render("ns1/named.conf", {"stale_test_zone": True})
    ns1.reconfigure()
    # stale-answer-client-timeout 0, stale-refresh-time 0
    templates.render("ns3/named.conf", template="ns3/named4.conf.j2")
    ns3.reconfigure()


def query_a(ns3: NamedInstance) -> dns.message.Message:
    msg = isctest.query.create(QNAME, "A", dnssec=False)
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.noerror(res)
    return res


def wait_until_stale() -> None:
    # The cache keeps expiry times in whole seconds, so a TTL 1 RRset is
    # stale at most one second after it has been cached, wherever in a
    # second that happened.
    time.sleep(2)


def wait_for_cached_cname(ns3: NamedInstance) -> None:
    # The dump also lists stale RRsets, so the CNAME is found whether or not
    # its TTL has run out by the time the dump is written.
    def cname_cached() -> bool:
        with ns3.watch_log_from_here() as watcher:
            ns3.rndc("dumpdb -cache")
            watcher.wait_for_line("dumpdb complete")
        dump = isctest.text.TextFile(f"{ns3.identifier}/named_dump.db")
        return bool(dump.grep(Re(r"\tCNAME\ta2\.stale\.test\.$")))

    isctest.run.retry_with_timeout(cname_cached, timeout=10)


def test_stale_cname_supersedes_stale_a(ns1: NamedInstance, ns3: NamedInstance):
    update = dns.update.UpdateMessage("stale.test.")
    update.add(QNAME, OLD_A)
    ns1.nsupdate(update)

    res = query_a(ns3)
    isctest.check.noede(res)
    assert res.answer == [OLD_A]

    update = dns.update.UpdateMessage("stale.test.")
    update.delete(QNAME, "A")
    update.add(QNAME, NEW_CNAME)
    ns1.nsupdate(update)

    wait_until_stale()

    # The stale A is answered straight from the cache, and the refresh
    # which follows caches the CNAME next to it.
    with ns3.watch_log_from_here() as watcher:
        res = query_a(ns3)
        watcher.wait_for_line(
            f"{QNAME.rstrip('.')} A stale answer used, "
            "an attempt to refresh the RRset will still be made"
        )
    isctest.check.ede(res, dns.edns.EDECode.STALE_ANSWER)
    assert res.answer == [OLD_A]
    wait_for_cached_cname(ns3)

    wait_until_stale()

    res = query_a(ns3)
    isctest.check.ede(res, dns.edns.EDECode.STALE_ANSWER)
    assert (
        res.answer[0] == NEW_CNAME
    ), "the stale A was served instead of the stale CNAME which replaced it"
