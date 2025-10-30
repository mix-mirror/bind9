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

import dns

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    QueryContext,
    ResponseDrop,
    ResponseHandler,
)


class ReplyA(ResponseHandler):
    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.A

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        a_rrset = dns.rrset.from_text(
            qctx.qname, 300, dns.rdataclass.IN, dns.rdatatype.A, "10.53.0.5"
        )
        qctx.response.answer.append(a_rrset)
        qctx.response.set_rcode(dns.rcode.NOERROR)
        yield DnsResponseSend(qctx.response)


class IgnoreNs(ResponseHandler):
    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.NS

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseDrop, None]:
        yield ResponseDrop()


class FallbackHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.set_rcode(dns.rcode.NOERROR)
        yield DnsResponseSend(qctx.response)


def main() -> None:
    server = AsyncDnsServer(default_aa=True)
    server.install_response_handler(ReplyA())
    server.install_response_handler(IgnoreNs())
    server.install_response_handler(FallbackHandler())
    server.run()


if __name__ == "__main__":
    main()
