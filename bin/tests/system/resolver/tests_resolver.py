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

from dns.edns import EDECode

import dns.message
import dns.rdatatype

import isctest


def test_resolver_cache_reloadfails(ns1, templates):
    ns1.rndc("flush")
    msg = isctest.query.create("www.example.org.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert res.answer[0].ttl == 300
    templates.render(
        "ns1/named.conf", {"wrongoption": True}, template="ns1/named2.conf.j2"
    )

    # The first reload fails, and the old cache list will be preserved
    cmd = ns1.rndc("reload", raise_on_exception=False)
    assert cmd.rc != 0

    templates.render("ns1/named.conf", {"wrongoption": False})
    # The second reload succeed, and the cache is still there, as preserved
    # from the old cache list
    ns1.rndc("reload")
    time.sleep(3)
    msg = isctest.query.create("www.example.org.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.noerror(res)

    # The ttl being lower than 300 (provided by fake authoritative) proves
    # the cache is still in use
    assert res.answer[0].ttl < 300


# GL#5930
def test_resolver_dname_target_filter_attack():
    # Control check - this should return 'attack.example.net. DNAME org.',
    # which then should result in resolving 'www.example.org. AAAA', which
    # should be SERVAIL because example.org is in 'deny-answer-aliases'.
    msg = isctest.query.create("www.example.attack.example.net.", "AAAA")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.servfail(res)

    # Execute the attack - this should return 'attack.example.net. DNAME org.',
    # which then should result in resolving isc.org and caching the DNAME.
    msg = isctest.query.create("isc.attack.example.net.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    answer = """;ANSWER
attack.example.net. 300 IN DNAME org.
isc.attack.example.net. 300 IN CNAME isc.org.
isc.org. 300 IN A 1.2.3.4
;AUTHORITY
;ADDITIONAL
"""
    expected_answer = dns.message.from_text(answer)
    isctest.check.noerror(res)
    isctest.check.rrsets_equal(res.answer, expected_answer.answer)
    isctest.check.rrsets_equal(res.authority, expected_answer.authority)
    isctest.check.rrsets_equal(res.additional, expected_answer.additional)

    # Vulnerability check - this should return 'attack.example.net. DNAME org.'
    # which then should result in resolving 'www.example.org. A', which
    # should still be SERVAIL because example.org is in 'deny-answer-aliases',
    # unless the attack on the previous step was successful.
    msg = isctest.query.create("www.example.attack.example.net.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.servfail(res)

    # Exception check - this should return 'gooddname.example.net. DNAME org.'
    # which then should result in resolving 'www.example.org. A', which
    # should be NOERROR because while example.org is in 'deny-answer-aliases',
    # gooddname.example.net is in the exceptions list.
    msg = isctest.query.create("www.example.gooddname.example.net.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.noerror(res)


def test_resolver_any_nodata(ns1):
    ns1.rndc("flush")

    # A resolver pretends the ANY type does not exist and always
    # answers with a NODATA response and EDE 21 (Not Supported); the
    # SOA type is resolved in place of ANY.
    msg = isctest.query.create("www.example.org.", "ANY")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.answer, 0)
    isctest.check.ede(res, EDECode.NOT_SUPPORTED)

    # ...including when the cache holds records for the queried name
    msg = isctest.query.create("www.example.org.", "A")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    assert res.answer[0].rdtype == dns.rdatatype.A

    msg = isctest.query.create("www.example.org.", "ANY")
    res = isctest.query.udp(msg, "10.53.0.1")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.answer, 0)
    isctest.check.ede(res, EDECode.NOT_SUPPORTED)


def test_resolver_any_nodata_soa_ttl():
    # an ANY query at a zone apex is answered with a NODATA response
    # built from the positive SOA; the SOA TTL in the authority
    # section must be capped at the SOA MINIMUM field (RFC 2308),
    # like in any other negative response (the zone has SOA TTL 600
    # and MINIMUM 60)
    msg = isctest.query.create("soa-minimum.", "ANY")
    res = isctest.query.udp(msg, "10.53.0.7")
    isctest.check.noerror(res)
    isctest.check.rr_count_eq(res.answer, 0)
    isctest.check.rr_count_eq(res.authority, 1)
    soa = res.authority[0]
    assert str(soa.name) == "soa-minimum."
    assert soa.rdtype == dns.rdatatype.SOA
    assert soa.ttl == 60
    isctest.check.ede(res, EDECode.NOT_SUPPORTED)
