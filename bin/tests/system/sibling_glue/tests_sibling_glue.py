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

import dns.rcode
import dns.rrset
import pytest

import isctest

# The "tld" zone served by ns2 contains cyclic sibling delegations:
# "foo.tld" is delegated to "ns.bar.tld" and "bar.tld" is delegated to
# "ns.foo.tld", so neither child zone can be reached without using the
# glue from the referral.


@pytest.mark.parametrize("resolver", ["ns4", "ns5"])
def test_sibling_glue_accepted_over_secured_channel(servers, resolver):
    # ns4 talks to the "tld" server over UDP protected by DNS COOKIE and
    # ns5 over TCP; both channels are protected against spoofing, so the
    # sibling glue from the referral is accepted and the cyclic sibling
    # delegations must be resolvable.
    for qname, address in (("a.foo.tld.", "192.0.2.1"), ("a.bar.tld.", "192.0.2.2")):
        msg = isctest.query.create(qname, "A")
        res = isctest.query.udp(msg, servers[resolver].ip)
        isctest.check.noerror(res)
        assert res.answer[0] == dns.rrset.from_text(qname, 300, "IN", "A", address)


def test_sibling_glue_rejected_over_spoofable_channel(servers):
    # ns6 talks to the "tld" server over UDP without DNS COOKIE; the
    # sibling glue from the referral must not be accepted over the
    # spoofable channel, so the cyclic sibling delegations are not
    # resolvable.
    msg = isctest.query.create("a.foo.tld.", "A")
    res = isctest.query.udp(msg, servers["ns6"].ip, expected_rcode=dns.rcode.SERVFAIL)
    isctest.check.servfail(res)
