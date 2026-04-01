"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from collections.abc import AsyncGenerator

import asyncio

import dns.rcode
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    QueryContext,
    ResponseAction,
    ResponseDrop,
    ResponseHandler,
)

LOCALADDR = "10.53.0.2"

# Delegations
SOA = "example. 300 IN SOA . . 0 0 0 0 300"
NS = "example. 300 IN NS ns.example."
A = f"ns.example. 300 IN A {LOCALADDR}"
SS_SOA = "delegated.serve.stale. 300 IN SOA . . 0 0 0 0 300"
SS_NS = "delegated.serve.stale. 300 IN NS ns.delegated.serve.stale."
SS_A = f"ns.delegated.serve.stale. 300 IN A {LOCALADDR}"

# Slow delegation
SLOW_SOA = "slow. 300 IN SOA . . 0 0 0 0 300"
SLOW_NS = "slow. 300 IN NS ns.slow."
SLOW_A = f"ns.slow. 300 IN A {LOCALADDR}"
SLOW_TXT = 'data.slow. 2 IN TXT "A slow text record with a 2 second ttl"'
SLOW_NEG_SOA = "slow. 2 IN SOA . . 0 0 0 0 300"

# Records to be TTL stretched
TXT = 'data.example. 2 IN TXT "A text record with a 2 second ttl"'
LONG_TXT = 'longttl.example. 600 IN TXT "A text record with a 600 second ttl"'
CAA = 'othertype.example. 2 IN CAA 0 issue "ca1.example.net"'
NEG_SOA = "example. 2 IN SOA . . 0 0 0 0 300"
SS_NEG_SOA = "delegated.serve.stale. 2 IN SOA . . 0 0 0 0 300"
CNAME = "cname.example. 7 IN CNAME target.example."
TARGET = f"target.example. 9 IN A {LOCALADDR}"
SHORT_CNAME = "shortttl.cname.example. 1 IN CNAME longttl.target.example."
LONG_TARGET = f"longttl.target.example. 600 IN A {LOCALADDR}"

# YWH records
YWH_SOA = "source.stale. 300 IN SOA . . 0 0 0 0 300"
YWH_NS = "source.stale. 300 IN NS ns.source.stale."
YWH_A = f"ns.source.stale. 300 IN A {LOCALADDR}"
YWH_CNAME = "alias.source.stale. 2 IN CNAME www.target.stale."
YWH_CNAME_NX = "aliasnx.source.stale. 2 IN CNAME nonexist.target.stale."


def rr(text):
    """Create an RRset from a text string like 'name. ttl IN TYPE rdata'."""
    parts = text.split(None, 4)
    return dns.rrset.from_text(parts[0], int(parts[1]), parts[2], parts[3], parts[4])


class ServeStaleHandler(ResponseHandler):
    def __init__(self):
        self.send_response = True
        self.slow_response = False

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        qname = str(qctx.qname).rstrip(".")
        qclass = qctx.qclass
        qtype = qctx.qtype
        response = qctx.response

        # Control commands -- always respond.
        if qname == "enable":
            self.send_response = True
            if qtype == dns.rdatatype.TXT:
                response.answer.append(
                    dns.rrset.from_text(qctx.qname, 0, qclass, dns.rdatatype.TXT, '"1"')
                )
            response.set_rcode(dns.rcode.NOERROR)
            yield DnsResponseSend(response, authoritative=True)
            return

        if qname == "disable":
            self.send_response = False
            if qtype == dns.rdatatype.TXT:
                response.answer.append(
                    dns.rrset.from_text(qctx.qname, 0, qclass, dns.rdatatype.TXT, '"0"')
                )
            response.set_rcode(dns.rcode.NOERROR)
            yield DnsResponseSend(response, authoritative=True)
            return

        if qname == "slowdown":
            self.send_response = True
            self.slow_response = True
            if qtype == dns.rdatatype.TXT:
                response.answer.append(
                    dns.rrset.from_text(qctx.qname, 0, qclass, dns.rdatatype.TXT, '"1"')
                )
            response.set_rcode(dns.rcode.NOERROR)
            yield DnsResponseSend(response, authoritative=True)
            return

        # If not responding, silently drop.
        if not self.send_response:
            yield ResponseDrop()
            return

        # Simulate network latency.
        if qname.startswith("latency"):
            await asyncio.sleep(0.05)

        # Build response.
        rcode = dns.rcode.NOERROR

        if qname == "ns.example":
            if qtype == dns.rdatatype.A:
                response.answer.append(rr(A))
            else:
                response.authority.append(rr(SOA))

        elif qname == "example":
            if qtype == dns.rdatatype.NS:
                response.authority.append(rr(NS))
                response.additional.append(rr(A))
            elif qtype == dns.rdatatype.SOA:
                response.answer.append(rr(SOA))
            else:
                response.authority.append(rr(SOA))

        elif qname == "nodata.example":
            response.authority.append(rr(NEG_SOA))

        elif qname == "data.example":
            if qtype == dns.rdatatype.TXT:
                response.answer.append(rr(TXT))
            else:
                response.authority.append(rr(NEG_SOA))

        elif qname == "a-only.example":
            if qtype == dns.rdatatype.A:
                response.answer.append(rr(f"a-only.example. 2 IN A {LOCALADDR}"))
            else:
                response.authority.append(rr(NEG_SOA))

        elif qname == "cname.example":
            if qtype == dns.rdatatype.A:
                response.answer.append(rr(CNAME))
            else:
                response.authority.append(rr(NEG_SOA))

        elif qname == "target.example":
            if self.slow_response:
                await asyncio.sleep(3)
            if qtype == dns.rdatatype.A:
                response.answer.append(rr(TARGET))
            else:
                response.authority.append(rr(NEG_SOA))

        elif qname == "shortttl.cname.example":
            response.answer.append(rr(SHORT_CNAME))

        elif qname == "longttl.target.example":
            if self.slow_response:
                await asyncio.sleep(3)
            if qtype == dns.rdatatype.A:
                response.answer.append(rr(LONG_TARGET))
            else:
                response.authority.append(rr(NEG_SOA))

        elif qname == "longttl.example":
            if qtype == dns.rdatatype.TXT:
                response.answer.append(rr(LONG_TXT))
            else:
                response.authority.append(rr(NEG_SOA))

        elif qname == "nxdomain.example":
            response.authority.append(rr(NEG_SOA))
            rcode = dns.rcode.NXDOMAIN

        elif qname == "othertype.example":
            if qtype == dns.rdatatype.CAA:
                response.answer.append(rr(CAA))
            else:
                response.authority.append(rr(NEG_SOA))

        elif qname == "ns.delegated.serve.stale":
            if qtype == dns.rdatatype.A:
                response.answer.append(rr(SS_A))
            else:
                response.authority.append(rr(SS_SOA))

        elif qname == "delegated.serve.stale":
            if qtype == dns.rdatatype.NS:
                response.authority.append(rr(SS_NS))
                response.additional.append(rr(SS_A))
            elif qtype == dns.rdatatype.SOA:
                response.answer.append(rr(SS_SOA))
            else:
                response.authority.append(rr(SS_SOA))

        elif qname == "www.delegated.serve.stale":
            if qtype == dns.rdatatype.A:
                response.answer.append(
                    rr("www.delegated.serve.stale. 2 IN A 10.53.0.99")
                )
            else:
                response.authority.append(rr(SS_NEG_SOA))

        elif qname == "cname.delegated.serve.stale":
            if qtype == dns.rdatatype.A:
                response.answer.append(
                    rr(
                        "cname.delegated.serve.stale. 2 IN CNAME cname-target.serve.stale."
                    )
                )
            else:
                response.authority.append(rr(SS_NEG_SOA))

        elif qname == "ns.slow":
            if qtype == dns.rdatatype.A:
                response.answer.append(rr(SLOW_A))
            else:
                response.authority.append(rr(SLOW_SOA))

        elif qname == "slow":
            if qtype == dns.rdatatype.NS:
                response.authority.append(rr(SLOW_NS))
                response.additional.append(rr(SLOW_A))
            elif qtype == dns.rdatatype.SOA:
                response.answer.append(rr(SLOW_SOA))
            else:
                response.authority.append(rr(SLOW_SOA))

        elif qname == "data.slow":
            if self.slow_response:
                await asyncio.sleep(3)
                # Only slow once.
                self.slow_response = False
            if qtype == dns.rdatatype.TXT:
                response.answer.append(rr(SLOW_TXT))
            else:
                response.authority.append(rr(SLOW_NEG_SOA))

        elif qname == "source.stale":
            if qtype == dns.rdatatype.SOA:
                response.answer.append(rr(YWH_SOA))
            elif qtype == dns.rdatatype.NS:
                response.answer.append(rr(YWH_NS))
                response.additional.append(rr(YWH_A))

        elif qname == "ns.source.stale":
            if qtype == dns.rdatatype.A:
                response.answer.append(rr(YWH_A))
            else:
                response.authority.append(rr(YWH_SOA))

        elif qname == "alias.source.stale":
            response.answer.append(rr(YWH_CNAME))

        elif qname == "aliasnx.source.stale":
            response.answer.append(rr(YWH_CNAME_NX))

        else:
            response.authority.append(rr(SOA))
            rcode = dns.rcode.NXDOMAIN

        response.set_rcode(rcode)
        yield DnsResponseSend(response, authoritative=True)


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(ServeStaleHandler())
    server.run()


if __name__ == "__main__":
    main()
