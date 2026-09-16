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

import asyncio

import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset
import dns.tsig
import pytest

from isctest.asyncserver import QueryContext, _make_asyncserver_response
from isctest.asyncserver.actions import DnsResponseSend
from isctest.asyncserver.context import DnsProtocol, Peer
from isctest.template import ANS1

import isctest


def query(qname: str) -> dns.message.Message:
    msg = isctest.query.create(qname, "A", dnssec=False, rd=False)
    return isctest.query.udp(msg, ANS1.ip, timeout=3, attempts=3)


def rrsets(
    section: list[dns.rrset.RRset], rdtype: dns.rdatatype.RdataType
) -> list[dns.rrset.RRset]:
    return [rrset for rrset in section if rrset.rdtype == rdtype]


def test_rollback_restores_the_response_from_zone_data():
    res = query("rollback.response.test.")
    isctest.check.noerror(res)
    assert res.flags & dns.flags.AA
    assert not rrsets(res.answer, dns.rdatatype.TXT)
    assert rrsets(res.answer, dns.rdatatype.A)[0][0].to_text() == "192.0.2.1"


def test_fresh_response_keeps_the_server_defaults():
    res = query("fresh.response.test.")
    isctest.check.rcode(res, dns.rcode.REFUSED)
    assert res.flags & dns.flags.AA
    isctest.check.empty_answer(res)
    assert not res.authority


def test_changes_after_rendering_reach_the_wire():
    res = query("rendered.response.test.")
    isctest.check.noerror(res)
    assert not res.flags & dns.flags.AA
    assert rrsets(res.answer, dns.rdatatype.A)
    assert rrsets(res.answer, dns.rdatatype.TXT)


def make_qctx() -> QueryContext:
    msg = dns.message.make_query("unit.test.", "A")
    return QueryContext(
        msg,
        _make_asyncserver_response(msg),
        {},
        {},
        Peer("10.53.0.1", 5300),
        Peer("10.53.0.1", 5300),
        DnsProtocol.UDP,
    )


def perform(action: DnsResponseSend) -> dns.message.Message | bytes | None:
    return asyncio.run(action.perform())


def test_hand_rolled_response_is_refused():
    response = dns.message.make_response(make_qctx().query)
    with pytest.raises(RuntimeError, match="prepare_new_response"):
        perform(DnsResponseSend(response))
    action = DnsResponseSend(response, acknowledge_hand_rolled_response=True)
    assert perform(action) is response


def test_prepared_new_response_is_accepted():
    qctx = make_qctx()
    qctx.save_initialized_response(with_zone_data=False)
    response = qctx.prepare_new_response(with_zone_data=False)
    assert response is not qctx.query
    assert perform(DnsResponseSend(response)) is response


def test_aa_change_on_a_signed_response_is_refused():
    response = make_qctx().response
    response.use_tsig(dns.tsig.Key("key.", "c2VjcmV0"))
    response.to_wire()
    assert response.tsig is not None
    with pytest.raises(RuntimeError, match="TSIG"):
        perform(DnsResponseSend(response, authoritative=True))
    assert perform(DnsResponseSend(response)) is response
