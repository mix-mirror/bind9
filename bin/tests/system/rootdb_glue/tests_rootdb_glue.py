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

"""
Regression test for the rrl system-test flake (GL #172) traced to
commit 0c007d8659 ("Rename view->hints to view->rootdb and rearm
priming").

When `dns_view_bestzonecut()` falls through to the rootdb fallback,
the delegset it returns must carry the root-server glue addresses so
the resolver can use them directly.  Without them, ADB launches a
sub-fetch for the missing address; that sub-fetch's own bestzonecut
also falls back to rootdb, gets the same NS_NAMES delegset, calls
findname() on the very name it is trying to resolve, and trips the
"loop detected resolving" path at lib/dns/resolver.c:3490.  The
parent fetch then fails with adberr and the client sees SERVFAIL.

The pattern that exposes the bug:

  * the hints file names the root server one way (`ns1.` in rrl, also
    here), with an A glue,
  * the actual root zone served by ns1 names its apex NS something
    different (`ns.` in rrl, also here),
  * for an apex `NS` query, BIND does not auto-include the in-zone
    glue for its own NS records in ADDITIONAL,
  * so after priming, rootdb has the new NS (`ns.`) but no matching
    glue.  Pre-fix the bestzonecut_rootdb delegset is NS_NAMES with
    that bare name and the next ADB sub-fetch loops.

Post-fix: dns_view_bestzonecut threads view->rootdb into
dns_delegset_fromnsrdataset, which pulls the `ns. A` glue (or the
fallback hints-file glue still present in rootdb) into an NS_GLUES
deleg, fctx_getaddresses_addresses uses it directly, and the query
succeeds.

The test fires a burst of distinct recursive queries straight after
named startup (matching the rrl-test trigger pattern of bursts arriving
during/just after priming).  Pre-fix many of them SERVFAIL; post-fix
all of them succeed.
"""

import concurrent.futures

import dns.flags

import isctest


BURST_SIZE = 20


def _ask(ns_ip, qname):
    msg = isctest.query.create(qname, "A")
    msg.flags |= dns.flags.RD
    return isctest.query.udp(msg, ns_ip)


def test_rootdb_glue_burst(ns2):
    qnames = [f"q{i:02d}.example." for i in range(BURST_SIZE)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=BURST_SIZE) as pool:
        responses = list(pool.map(lambda q: _ask(ns2.ip, q), qnames))

    # The example zone contains only `a.example.`, so each query should
    # resolve to NXDOMAIN — but a CLEAN NXDOMAIN from the example
    # authoritative server, not a SERVFAIL caused by the resolver
    # tripping its own loop detection.
    bad = [
        (q, r.rcode().name)
        for q, r in zip(qnames, responses)
        if r.rcode().name == "SERVFAIL"
    ]
    assert not bad, (
        f"{len(bad)}/{BURST_SIZE} burst queries SERVFAILed; "
        f"first few: {bad[:3]}.  Check ns2/named.run for "
        f"'loop detected resolving' — that's the rrl flake signature."
    )
