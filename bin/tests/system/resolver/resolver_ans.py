"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from typing import AsyncGenerator, List, Union

import abc

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    DnsResponseSend,
    DomainHandler,
    QnameHandler,
    QueryContext,
)


def rrset(
    qname: Union[dns.name.Name, str], rtype: dns.rdatatype.RdataType, rdata: str
) -> dns.rrset.RRset:
    return dns.rrset.from_text(qname, 300, dns.rdataclass.IN, rtype, rdata)


def rrset_from_list(
    qname: Union[dns.name.Name, str],
    rtype: dns.rdatatype.RdataType,
    rdata_list: List[str],
) -> dns.rrset.RRset:
    return dns.rrset.from_text_list(qname, 300, dns.rdataclass.IN, rtype, rdata_list)


def soa_rrset(qname: Union[dns.name.Name, str]) -> dns.rrset.RRset:
    return rrset(qname, dns.rdatatype.SOA, ". . 0 0 0 0 0")


def delegation_rrsets(
    owner: Union[dns.name.Name, str], server_number: int
) -> tuple[dns.rrset.RRset, dns.rrset.RRset]:
    ns_name = f"ns.{owner}"
    ns_rrset = rrset(owner, dns.rdatatype.NS, ns_name)
    a_rrset = rrset(ns_name, dns.rdatatype.A, f"10.53.0.{server_number}")
    return ns_rrset, a_rrset


def setup_delegation(
    qctx: QueryContext, owner: Union[dns.name.Name, str], server_number: int
) -> None:
    ns_rrset, a_rrset = delegation_rrsets(owner, server_number)
    qctx.response.authority.append(ns_rrset)
    qctx.response.additional.append(a_rrset)


class DelegationHandler(DomainHandler):
    @property
    @abc.abstractmethod
    def server_number(self) -> int:
        raise NotImplementedError

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        setup_delegation(qctx, self.matching_domain, self.server_number)
        yield DnsResponseSend(qctx.response, authoritative=False)


class Gl6412AHandler(QnameHandler):
    qnames = ["a.gl6412.", "a.a.gl6412."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.authority.append(soa_rrset(qctx.qname))
        yield DnsResponseSend(qctx.response, authoritative=False)


class Gl6412Handler(QnameHandler):
    qnames = ["gl6412."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if qctx.qtype == dns.rdatatype.SOA:
            qctx.response.answer.append(soa_rrset(qctx.qname))
        elif qctx.qtype == dns.rdatatype.NS:
            # XXX: The delegation is broken here; dot is missing from NS target names.
            # I don't know if this is intentional, but for now we are chasing behavior parity.
            ns2_rrset = rrset(qctx.qname, dns.rdatatype.NS, f"ns2{qctx.qname}")
            ns3_rrset = rrset(qctx.qname, dns.rdatatype.NS, f"ns3{qctx.qname}")
            qctx.response.answer.append(ns2_rrset)
            qctx.response.answer.append(ns3_rrset)
        else:
            qctx.response.authority.append(soa_rrset(qctx.qname))
        yield DnsResponseSend(qctx.response, authoritative=False)


class Gl6412Ns2Handler(QnameHandler):
    qnames = ["ns2.gl6412."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if qctx.qtype == dns.rdatatype.A:
            a_rrset = rrset(qctx.qname, dns.rdatatype.A, "10.53.0.2")
            qctx.response.answer.append(a_rrset)
        else:
            qctx.response.authority.append(soa_rrset(qctx.qname))
        yield DnsResponseSend(qctx.response, authoritative=False)


class Gl6412Ns3Handler(QnameHandler):
    qnames = ["ns3.gl6412."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if qctx.qtype == dns.rdatatype.A:
            a_rrset = rrset(qctx.qname, dns.rdatatype.A, "10.53.0.3")
            qctx.response.answer.append(a_rrset)
        else:
            qctx.response.authority.append(soa_rrset(qctx.qname))
        yield DnsResponseSend(qctx.response, authoritative=False)
