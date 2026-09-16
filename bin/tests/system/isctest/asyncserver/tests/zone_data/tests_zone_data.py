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

import dns.message
import dns.rdatatype
import dns.rrset

from isctest.template import ANS1

import isctest


def query(qname: str, qtype: str) -> dns.message.Message:
    msg = isctest.query.create(qname, qtype, dnssec=False, rd=False)
    return isctest.query.udp(msg, ANS1.ip, timeout=3, attempts=3)


def rrsets(
    section: list[dns.rrset.RRset], rdtype: dns.rdatatype.RdataType
) -> list[dns.rrset.RRset]:
    return [rrset for rrset in section if rrset.rdtype == rdtype]


def test_cname_chain_is_followed():
    res = query("foo.example.", "A")
    isctest.check.noerror(res)
    assert [rrset.rdtype for rrset in res.answer] == [
        dns.rdatatype.CNAME,
        dns.rdatatype.A,
    ]
    assert rrsets(res.answer, dns.rdatatype.A)[0][0].to_text() == "192.0.2.2"
