"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from typing import AsyncGenerator

import dns.name
import dns.rcode
import dns.rdatatype

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    DomainHandler,
    IgnoreAllQueries,
    QnameHandler,
    QnameQtypeHandler,
    QueryContext,
    StaticResponseHandler,
    ResponseHandler,
)

from resolver_ans import (
    DelegationHandler,
    Gl6412AHandler,
    Gl6412Handler,
    Gl6412Ns2Handler,
    Gl6412Ns3Handler,
    delegation_rrsets,
    rrset,
    rrset_from_list,
    soa_rrset,
)


class ApexNSHandler(QnameHandler, StaticResponseHandler):
    qnames = ["example.net."]
    qtypes = [dns.rdatatype.NS]
    _ns_rrset, _a_rrset = delegation_rrsets("example.net.", 3)
    answer = [_ns_rrset]
    additional = [_a_rrset]


class BadCnameHandler(QnameHandler, StaticResponseHandler):
    qnames = ["badcname.example.net."]
    answer = [rrset(qnames[0], dns.rdatatype.CNAME, "badcname.example.org.")]


class BadGoodDnameNsHandler(QnameQtypeHandler):
    qnames = ["baddname.example.net.", "gooddname.example.net."]
    qtypes = [dns.rdatatype.NS]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.authority.append(soa_rrset(qctx.qname))
        yield DnsResponseSend(qctx.response)


class CnameSubHandler(QnameHandler, StaticResponseHandler):
    qnames = ["cname.sub.example.org."]
    answer = [rrset(qnames[0], dns.rdatatype.CNAME, "ok.sub.example.org.")]


class FooBadDnameHandler(QnameHandler, StaticResponseHandler):
    qnames = ["foo.baddname.example.net."]
    answer = [
        rrset("baddname.example.net.", dns.rdatatype.DNAME, "baddname.example.org.")
    ]


class FooBarSubTld1Handler(QnameHandler):
    qnames = ["foo.bar.sub.tld1."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(
            rrset("foo.bar.sub.tld1.", dns.rdatatype.TXT, "baz")
        )
        yield DnsResponseSend(qctx.response)


class FooGlueInAnswerHandler(QnameHandler, StaticResponseHandler):
    qnames = ["foo.glue-in-answer.example.org."]
    answer = [rrset(qnames[0], dns.rdatatype.A, "192.0.2.1")]


class FooGoodDnameHandler(QnameHandler, StaticResponseHandler):
    qnames = ["foo.gooddname.example.net."]
    answer = [
        rrset("gooddname.example.net.", dns.rdatatype.DNAME, "gooddname.example.org.")
    ]


class GoodCnameHandler(QnameHandler, StaticResponseHandler):
    qnames = ["goodcname.example.net."]
    answer = [rrset(qnames[0], dns.rdatatype.CNAME, "goodcname.example.org.")]


class LameExampleOrgDelegation(DelegationHandler):
    domains = ["lame.example.org."]
    server_number = 3


class LargeReferralHandler(QnameHandler, StaticResponseHandler):
    qnames = ["large-referral.example.net."]
    qtypes = [dns.rdatatype.NS]
    answer = [
        rrset_from_list(
            qnames[0],
            dns.rdatatype.NS,
            [f"ns{i}.redirect.com." for i in range(1, 1000)],
        )
    ]


class LongCnameHandler(ResponseHandler):
    def match(self, qctx: QueryContext) -> bool:
        return qctx.qname.labels[0] == b"longcname"

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        cname_target = f"{dns.name.Name(b"longcnamex" + qctx.qname.labels[1:])}"
        qctx.response.answer.append(
            rrset(qctx.qname, dns.rdatatype.CNAME, cname_target)
        )
        yield DnsResponseSend(qctx.response)


class NodataHandler(QnameHandler, StaticResponseHandler):
    qnames = ["nodata.example.net."]


class NoresponseHandler(QnameHandler, IgnoreAllQueries):
    qnames = ["noresponse.example.net."]


class NsHandler(QnameHandler, StaticResponseHandler):
    qnames = ["ns.example.net."]
    _, _a_rrset = delegation_rrsets("example.net.", 3)
    answer = [_a_rrset]


class NxdomainHandler(QnameHandler, StaticResponseHandler):
    qnames = ["nxdomain.example.net."]
    rcode = dns.rcode.NXDOMAIN


class OkSubHandler(QnameHandler, StaticResponseHandler):
    qnames = ["ok.sub.example.org."]
    answer = [rrset("ok.sub.example.org.", dns.rdatatype.A, "192.0.2.1")]


class PartialFormerrHandler(DomainHandler, StaticResponseHandler):
    domains = ["partial-formerr."]
    answer = [rrset("partial-formerr.", dns.rdatatype.A, "10.53.0.3")]


class WwwDnameSubHandler(QnameHandler, StaticResponseHandler):
    qnames = ["www.dname.sub.example.org."]
    answer = [rrset("sub.example.org.", dns.rdatatype.DNAME, "ok.sub.example.org.")]


class WwwHandler(QnameHandler):
    qnames = ["www.example.net."]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        if qctx.qtype == dns.rdatatype.A:
            qctx.response.answer.append(
                rrset("www.example.net.", dns.rdatatype.A, "192.0.2.1")
            )
        elif qctx.qtype == dns.rdatatype.AAAA:
            qctx.response.answer.append(
                rrset("www.example.net.", dns.rdatatype.AAAA, "2001:db8:beef::1")
            )
        yield DnsResponseSend(qctx.response)


class FallbackHandler(StaticResponseHandler):
    answer = [rrset("www.example.com.", dns.rdatatype.A, "1.2.3.4")]


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        ApexNSHandler(),
        BadCnameHandler(),
        BadGoodDnameNsHandler(),
        CnameSubHandler(),
        FooBadDnameHandler(),
        FooGoodDnameHandler(),
        FooGlueInAnswerHandler(),
        Gl6412AHandler,
        Gl6412Handler,
        Gl6412Ns2Handler,
        Gl6412Ns3Handler,
        GoodCnameHandler(),
        LameExampleOrgDelegation(),
        LargeReferralHandler(),
        LongCnameHandler(),
        NodataHandler(),
        NoresponseHandler(),
        NsHandler(),
        NxdomainHandler(),
        OkSubHandler(),
        PartialFormerrHandler(),
        WwwDnameSubHandler(),
        WwwHandler(),
    )

    server.install_response_handler(FallbackHandler())
    server.run()


if __name__ == "__main__":
    main()
