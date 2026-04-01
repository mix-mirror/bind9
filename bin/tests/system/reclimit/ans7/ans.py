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


class CounterHandler(ResponseHandler):
    """Simple query counter for NS explosion testing."""

    def __init__(self):
        self.count = 0

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        qname = str(qctx.qname).rstrip(".")
        response = qctx.response
        self.count += 1

        if qname == "count":
            if qctx.qtype == dns.rdatatype.TXT:
                response.answer.append(
                    dns.rrset.from_text(
                        qctx.qname,
                        0,
                        qctx.qclass,
                        dns.rdatatype.TXT,
                        str(self.count),
                    )
                )
            response.set_rcode(dns.rcode.NOERROR)
        elif qname == "reset":
            self.count = 0
            response.set_rcode(dns.rcode.NOERROR)
        else:
            response.set_rcode(dns.rcode.REFUSED)

        yield DnsResponseSend(response, authoritative=True)


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.REFUSED)
    server.install_response_handlers(CounterHandler())
    server.run()


if __name__ == "__main__":
    main()
