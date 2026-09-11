#!/usr/bin/python3

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

import dns.rdatatype
import pytest

import isctest
import isctest.template
import isctest.zone

TESTZONE = "noqname.test."
QNAME = f"foo.{TESTZONE}"
RESOLVER = isctest.template.NS2.ip

pytestmark = [
    pytest.mark.extra_artifacts(
        [
            "ans*/ans.run",
            "ans*/dsset-*",
            "ans*/keys/",
            "ans*/zones/*.db",
            "ans*/zones/*.db.signed",
        ]
    ),
]


def bootstrap():
    zone = isctest.zone.Zone(TESTZONE, isctest.template.ANS1, signed=True)
    zone.configure(csk=True)

    return {"trust_anchors": zone.trust_anchors()}


def _query(qname, qtype):
    query = isctest.query.create(qname, qtype)
    return isctest.query.tcp(query, RESOLVER)


def test_noqname_proof_any_from_cache():
    """
    Cache two wildcard-synthesized RRsets for the same name, then query for
    ANY.  Both cached rdatasets carry the same noqname proof, so
    query_addnoqnameproof() runs twice for one response and the second call
    finds the NSEC already present in the AUTHORITY section.  The rdatasets
    allocated for that second attempt must be freed; when they leak, ns2
    aborts at shutdown (dns_message_destroypools() assertion), which shows
    up as a core dump after this module finishes.
    """
    for qtype in ("A", "TXT"):
        response = _query(QNAME, qtype)
        isctest.check.noerror(response)
        isctest.check.adflag(response)
        assert any(
            rrset.rdtype == dns.rdatatype.from_text(qtype) for rrset in response.answer
        ), response.to_text()

    response = _query(QNAME, "ANY")
    isctest.check.noerror(response)
    isctest.check.adflag(response)
    answer_types = {rrset.rdtype for rrset in response.answer}
    assert dns.rdatatype.A in answer_types, response.to_text()
    assert dns.rdatatype.TXT in answer_types, response.to_text()
    nsecs = [
        rrset for rrset in response.authority if rrset.rdtype == dns.rdatatype.NSEC
    ]
    assert len(nsecs) == 1, response.to_text()
