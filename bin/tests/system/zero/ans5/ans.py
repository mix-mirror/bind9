"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

import ipaddress
from typing import AsyncGenerator

import dns.flags
import dns.message
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    QueryContext,
    ResponseHandler,
)


class IncrementARecordHandler(ResponseHandler):
    """
    To test the TTL=0 behavior, increment the IPv4 address by one every
    time we get queried.
    """

    def __init__(self):
        self._ipaddress = ipaddress.ip_address("192.0.2.0")

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        response = qctx.query
        response.flags |= dns.flags.QR
        response.flags |= dns.flags.AA

        qname = response.question[0].name
        qtype = response.question[0].rdtype

        rrset = dns.rrset.RRset(qname, dns.rdataclass.IN, dns.rdatatype.A)
        rrset.ttl = 0
        rrset.add(
            dns.rdata.from_text(
                dns.rdataclass.IN, dns.rdatatype.A, str(self._ipaddress)
            )
        )
        response.answer.append(rrset)

        self._ipaddress += 1
        yield DnsResponseSend(response)


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handler(IncrementARecordHandler())
    server.run()


if __name__ == "__main__":
    main()
