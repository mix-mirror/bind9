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

import re
import isctest
from dns.rcode import REFUSED, NOERROR

AEXAMPLE5_RR = "a.example5. 300 IN A 10.53.0.50"
NSEXAMPLE5_RR = "example5. 300 IN NS ns.example5."

AEXAMPLE42_RR = "a.example4-2. 300 IN A 10.53.0.42"

EXAMPLE2_NS = "example2. 300 IN NS ns.example2."
AEXAMPLE2_A = "a.example2. 300 IN A 10.53.0.20"
NSEXAMPLE2_A = "ns.example2. 300 IN A 10.53.0.2"

EXAMPLE4_NS = "example4. 300 IN NS ns.example4."
AEXAMPLE4_A = "a.example4. 300 IN A 10.53.0.40"
NSEXAMPLE4_A = "ns.example4. 300 IN A 10.53.0.4"

AROOTSERVER_NS = ". 999999 IN NS a.root-servers.nil."

INPUTPARAMS = "ns, qname, qtype, rd, cached, rcode, answer, authority, additional"

# `minimal-responses yes` and `minimal-responses no-auth` behaves the same,
# hence they share the same input.
# The only case AUTHORITY and ADDITIONAL are provided are when strictly needed:
#   - either from an authoritative server for delegation
#     (cases with ns1, both AUTHORITY and glues in ADDITIONAL);
#   - either from a resolver with RD=0 and no cache,
#      so the resolver can only return the root hints (AUTHORITY only).
INPUTS_YES_NOAUTH = [
    ("ns1", "a.example2", "A", True, False, NOERROR, None, EXAMPLE2_NS, NSEXAMPLE2_A),
    ("ns1", "a.example4", "A", True, False, NOERROR, None, EXAMPLE4_NS, NSEXAMPLE4_A),
    ("ns2", "a.example2", "A", True, False, NOERROR, AEXAMPLE2_A, None, None),
    ("ns2", "a.example4", "A", True, False, REFUSED, None, None, None),
    ("ns3", "a.example2", "A", True, False, NOERROR, AEXAMPLE2_A, None, None),
    ("ns3", "a.example4", "A", True, False, NOERROR, AEXAMPLE4_A, None, None),
    ("ns3", "a.example2", "A", True, True, NOERROR, AEXAMPLE2_A, None, None),
    ("ns3", "a.example4", "A", True, True, NOERROR, AEXAMPLE4_A, None, None),
    ("ns4", "a.example2", "A", True, False, NOERROR, AEXAMPLE2_A, None, None),
    ("ns4", "a.example4", "A", True, False, NOERROR, AEXAMPLE4_A, None, None),
    ("ns4", "a.example2", "A", True, True, NOERROR, AEXAMPLE2_A, None, None),
    ("ns4", "a.example4", "A", True, True, NOERROR, AEXAMPLE4_A, None, None),
    ("ns1", "a.example2", "A", False, False, NOERROR, None, EXAMPLE2_NS, NSEXAMPLE2_A),
    ("ns1", "a.example4", "A", False, False, NOERROR, None, EXAMPLE4_NS, NSEXAMPLE4_A),
    ("ns2", "a.example2", "A", False, False, NOERROR, AEXAMPLE2_A, None, None),
    ("ns2", "a.example4", "A", False, False, REFUSED, None, None, None),
    ("ns3", "a.example2", "A", False, False, NOERROR, None, AROOTSERVER_NS, None),
    ("ns3", "a.example4", "A", False, False, NOERROR, None, AROOTSERVER_NS, None),
    ("ns3", "a.example2", "A", False, True, NOERROR, AEXAMPLE2_A, None, None),
    ("ns3", "a.example4", "A", False, True, NOERROR, AEXAMPLE4_A, None, None),
    ("ns4", "a.example2", "A", False, False, NOERROR, None, AROOTSERVER_NS, None),
    ("ns4", "a.example4", "A", False, False, NOERROR, AEXAMPLE4_A, None, None),
    ("ns4", "a.example2", "A", False, True, NOERROR, AEXAMPLE2_A, None, None),
    ("ns4", "a.example4", "A", False, True, NOERROR, AEXAMPLE4_A, None, None),
]

TESTSERVERS = None

FLUSHED_PATTERN = re.compile("flushing cache.*succeeded")


def check_no_additional(ns1, has_additional, ns3):
    msg = isctest.query.create("a.example4-2.", "A")
    res = isctest.query.udp(msg, ns3.ip)
    isctest.check.rcode(res, NOERROR)
    assert len(res.answer) == 1
    res.answer[0].ttl = 300
    assert str(res.answer[0] == AEXAMPLE42_RR)
    assert len(res.additional) == 0
    msg = isctest.query.create("a.example5.", "A")
    res = isctest.query.udp(msg, ns1.ip)
    isctest.check.rcode(res, NOERROR)
    assert len(res.answer) == 1
    res.answer[0].ttl = 300
    assert str(res.answer[0] == AEXAMPLE5_RR)
    if has_additional:
        assert len(res.additional) == 1
        res.additional[0].ttl = 300
        assert str(res.additional[0] == NSEXAMPLE5_RR)
    else:
        assert len(res.additional) == 0


def check(ns, qname, qtype, rd, cached, rcode, answer, authority, additional):
    ns = TESTSERVERS[ns]
    msg = isctest.query.create(qname, "A", rd=rd)
    if cached:
        cachingmsg = isctest.query.create(qname, "A", rd=True)
        isctest.query.udp(cachingmsg, ns.ip)
    else:
        with ns.watch_log_from_here() as watcher:
            ns.rndc("flush")
            watcher.wait_for_line(FLUSHED_PATTERN)
    res = isctest.query.udp(msg, ns.ip)
    isctest.check.rcode(res, rcode)
    if answer:
        assert len(res.answer) == 1
        assert str(res.answer[0]) == answer
    else:
        assert len(res.answer) == 0
    if authority:
        assert len(res.authority) == 1
        assert str(res.authority[0]) == authority
    else:
        assert len(res.authority) == 0
    if additional:
        assert len(res.additional) == 1
        assert str(res.additional[0]) == additional
    else:
        assert len(res.additional) == 0


def reconfig(servers, templates, minresp):
    global TESTSERVERS
    for server in servers:
        ns = servers[server]
        with ns.watch_log_from_here() as watcher:
            templates.render(f"{server}/named.conf", {"minresp": minresp})
            ns.rndc("reload")
            watcher.wait_for_line("running")
    TESTSERVERS = servers
