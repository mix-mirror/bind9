"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from typing import AsyncGenerator, Tuple, Union

import abc

import dns.edns
import dns.name
import dns.rcode
import dns.rrset
import dns.rdataclass
import dns.rdatatype

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    DomainHandler,
    IgnoreAllQueries,
    QnameHandler,
    QueryContext,
    ResponseHandler,
)


def rrset(
    qname: Union[dns.name.Name, str], rtype: dns.rdatatype.RdataType, rdata: str
) -> dns.rrset.RRset:
    return dns.rrset.from_text(qname, 300, dns.rdataclass.IN, rtype, rdata)


class BadGoodDnameNsHandler(QnameHandler):
    qnames = [
        "baddname.example.org.",
        "gooddname.example.org.",
    ]

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.NS and super().match(qctx)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        root_ns = rrset("example.org.", dns.rdatatype.NS, "a.root-servers.nil.")
        qctx.response.answer.append(root_ns)
        yield DnsResponseSend(qctx.response, authoritative=True)


def cname_rrsets(qname: dns.name.Name) -> Tuple[dns.rrset.RRset, dns.rrset.RRset]:
    return (
        rrset(qname, dns.rdatatype.CNAME, f"{qname}"),
        rrset(qname, dns.rdatatype.A, "1.2.3.4"),
    )


class Cname1Handler(QnameHandler):
    qnames = ["cname1.example.com."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        # Data for the "cname + other data / 1" test
        cname_rrset, a_rrset = cname_rrsets(qctx.qname)
        qctx.response.answer.append(cname_rrset)
        qctx.response.answer.append(a_rrset)
        yield DnsResponseSend(qctx.response, authoritative=False)


class Cname2Handler(QnameHandler):
    qnames = ["cname2.example.com."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        # Data for the "cname + other data / 2" test: same RRs in opposite order
        cname_rrset, a_rrset = cname_rrsets(qctx.qname)
        qctx.response.answer.append(a_rrset)
        qctx.response.answer.append(cname_rrset)
        yield DnsResponseSend(qctx.response, authoritative=False)


class ExampleOrgHandler(QnameHandler):
    qnames = [
        "www.example.org",
        "badcname.example.org",
        "goodcname.example.org",
        "foo.baddname.example.org",
        "foo.gooddname.example.org",
    ]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        # Data for address/alias filtering.
        if qctx.qtype == dns.rdatatype.A:
            a_rrset = rrset(qctx.qname, dns.rdatatype.A, "192.0.2.1")
            qctx.response.answer.append(a_rrset)
        elif qctx.qtype == dns.rdatatype.AAAA:
            aaaa_rrset = rrset(qctx.qname, dns.rdatatype.AAAA, "2001:db8:beef::1")
            qctx.response.answer.append(aaaa_rrset)
        yield DnsResponseSend(qctx.response, authoritative=True)


def soa_rrset(qname: Union[dns.name.Name, str]) -> dns.rrset.RRset:
    return rrset(qname, dns.rdatatype.SOA, ". . 0 0 0 0 0")


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


class NoResponseExampleUdpHandler(QnameHandler, IgnoreAllQueries):
    qnames = ["noresponse.exampleudp.net."]


class RootNsHandler(QnameHandler):
    qnames = [
        "example.com.",
        "com.",
        "example.org.",
        "org.",
        "net.",
    ]

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.NS and super().match(qctx)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        root_ns = rrset(qctx.qname, dns.rdatatype.NS, "a.root-servers.nil.")
        qctx.response.answer.append(root_ns)
        yield DnsResponseSend(qctx.response, authoritative=True)


class ZoneVersionHandler(QnameHandler):
    qnames = ["zoneversion."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.authority.append(soa_rrset("."))
        zoneversion_opt = dns.edns.GenericOption(19, bytes.fromhex("000101022304"))  # type: ignore
        qctx.response.use_edns(edns=0, options=[zoneversion_opt])
        yield DnsResponseSend(qctx.response, authoritative=False)


def setup_delegation(
    qctx: QueryContext, owner: Union[dns.name.Name, str], server_number: int
) -> None:
    ns_name = f"ns.{owner}"
    ns_rrset = rrset(owner, dns.rdatatype.NS, ns_name)
    a_rrset = rrset(ns_name, dns.rdatatype.A, f"10.53.0.{server_number}")
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


class Ns2Delegation(DelegationHandler):
    domains = ["exampleudp.net."]
    server_number = 2


class Ns3Delegation(DelegationHandler):
    domains = [
        "example.net.",
        "lame.example.org.",
        "sub.example.org.",
    ]
    server_number = 3


class Ns3GlueInAnswerDelegation(DelegationHandler):
    domains = ["glue-in-answer.example.org."]
    server_number = 3

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        async for dns_response in super().get_responses(qctx):
            dns_response.response.answer += dns_response.response.additional
            yield dns_response


class Ns4Delegation(DelegationHandler):
    domains = ["broken."]
    server_number = 4


class Ns6Delegation(DelegationHandler):
    domains = [
        "redirect.com.",
        "tld1.",
    ]
    server_number = 6


class Ns7Delegation(DelegationHandler):
    domains = ["tld2."]
    server_number = 7


class PartialFormerrHandler(DomainHandler):
    domains = ["partial-formerr."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.set_rcode(dns.rcode.FORMERR)
        yield DnsResponseSend(qctx.response, authoritative=False)


class FallbackHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        setup_delegation(qctx, "below.www.example.com.", 3)
        yield DnsResponseSend(qctx.response, authoritative=False)


# XXX: This handler is here to provide bug-for-bug compatibility with the old server.
class XXXBuggyTldNsHandler(QnameHandler, FallbackHandler):
    qnames = [
        "tld1.",
        "tld2.",
    ]

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.NS and super().match(qctx)


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR)

    # Install QnameHandlers first
    server.install_response_handlers(
        BadGoodDnameNsHandler(),
        Cname1Handler(),
        Cname2Handler(),
        ExampleOrgHandler(),
        Gl6412AHandler(),
        Gl6412Handler(),
        Gl6412Ns2Handler(),
        Gl6412Ns3Handler(),
        NoResponseExampleUdpHandler(),
        RootNsHandler(),
        ZoneVersionHandler(),
        XXXBuggyTldNsHandler(),
    )

    # Then install DomainHandlers
    server.install_response_handlers(
        Ns2Delegation(),
        Ns3Delegation(),
        Ns3GlueInAnswerDelegation(),
        Ns4Delegation(),
        Ns6Delegation(),
        Ns7Delegation(),
        PartialFormerrHandler(),
    )

    # Finally, install the fallback handler
    server.install_response_handler(FallbackHandler())
    server.run()


if __name__ == "__main__":
    main()
