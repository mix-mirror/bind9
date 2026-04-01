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

import dns.rcode
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    QueryContext,
    ResponseAction,
    ResponseHandler,
)

LOCALADDR = "10.53.0.8"

# YWH records
YWH_SOA = "target.stale. 300 IN SOA . . 0 0 0 0 300"
YWH_NS = "target.stale. 300 IN NS ns.target.stale."
YWH_A = f"ns.target.stale. 300 IN A {LOCALADDR}"
YWH_WWW_DEFAULT = "www.target.stale. 2 IN A 10.0.0.1"
YWH_WWW_UPDATED = "www.target.stale. 2 IN A 10.0.0.2"


def rr(text):
    """Create an RRset from a text string like 'name. ttl IN TYPE rdata'."""
    parts = text.split(None, 4)
    return dns.rrset.from_text(parts[0], int(parts[1]), parts[2], parts[3], parts[4])


class TargetStaleHandler(ResponseHandler):
    def __init__(self):
        self.www_record = YWH_WWW_DEFAULT

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        qname = str(qctx.qname).rstrip(".")
        qclass = qctx.qclass
        qtype = qctx.qtype
        response = qctx.response

        # Control commands.
        if qname == "update":
            self.www_record = YWH_WWW_UPDATED
            if qtype == dns.rdatatype.TXT:
                response.answer.append(
                    dns.rrset.from_text(
                        qctx.qname, 0, qclass, dns.rdatatype.TXT, '"update"'
                    )
                )
            response.set_rcode(dns.rcode.NOERROR)
            yield DnsResponseSend(response, authoritative=True)
            return

        if qname == "restore":
            self.www_record = YWH_WWW_DEFAULT
            if qtype == dns.rdatatype.TXT:
                response.answer.append(
                    dns.rrset.from_text(
                        qctx.qname, 0, qclass, dns.rdatatype.TXT, '"restore"'
                    )
                )
            response.set_rcode(dns.rcode.NOERROR)
            yield DnsResponseSend(response, authoritative=True)
            return

        # Normal responses.
        rcode = dns.rcode.NOERROR

        if qname == "target.stale":
            if qtype == dns.rdatatype.SOA:
                response.answer.append(rr(YWH_SOA))
            elif qtype == dns.rdatatype.NS:
                response.answer.append(rr(YWH_NS))
                response.additional.append(rr(YWH_A))

        elif qname == "ns.target.stale":
            if qtype == dns.rdatatype.A:
                response.answer.append(rr(YWH_A))
            else:
                response.authority.append(rr(YWH_SOA))

        elif qname == "www.target.stale":
            if qtype == dns.rdatatype.A:
                response.answer.append(rr(self.www_record))
            else:
                response.authority.append(rr(YWH_SOA))

        else:
            response.authority.append(rr(YWH_SOA))
            rcode = dns.rcode.NXDOMAIN

        response.set_rcode(rcode)
        yield DnsResponseSend(response, authoritative=True)


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(TargetStaleHandler())
    server.run()


if __name__ == "__main__":
    main()
