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
from pathlib import Path

import asyncio
import re

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

LOCALADDR = "10.53.0.4"


class RecursionChainHandler(ResponseHandler):
    """Simpler variant of the ans2 chain handler.

    Key difference from ans2: when limit > 0, chain queries always
    return the final A record immediately (send_response starts True).
    Uses the same delayed response batching for chain queries.
    """

    def __init__(self):
        self.count = 0
        self.send_response = True
        self.limit = self._read_limit()
        self._delayed_event = asyncio.Event()
        self._delayed_pending = False
        self._no_more_waiting = False

    @staticmethod
    def _read_limit():
        limit_file = Path("ans.limit")
        if limit_file.exists():
            text = limit_file.read_text().strip()
            if text.isdigit():
                return int(text)
        return 0

    async def _maybe_delay(self):
        """Implement the delayed response batching for chain queries."""
        if self._no_more_waiting:
            return

        if self._delayed_pending:
            self._delayed_event.set()
            return

        self._delayed_pending = True
        self._delayed_event.clear()
        try:
            await asyncio.wait_for(self._delayed_event.wait(), timeout=0.5)
        except asyncio.TimeoutError:
            self._no_more_waiting = True
        finally:
            self._delayed_pending = False

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        qname = str(qctx.qname).rstrip(".")
        response = qctx.response
        self.count += 1
        wait = False

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
            self.send_response = True
            self.limit = self._read_limit()
            response.set_rcode(dns.rcode.NOERROR)

        elif qname == "direct.example.org":
            if qctx.qtype == dns.rdatatype.A:
                response.answer.append(
                    dns.rrset.from_text(
                        qctx.qname,
                        3600,
                        qctx.qclass,
                        dns.rdatatype.A,
                        LOCALADDR,
                    )
                )
            response.set_rcode(dns.rcode.NOERROR)

        elif re.match(r"^indirect[1-8]\.example\.org$", qname):
            if qctx.qtype == dns.rdatatype.A:
                response.answer.append(
                    dns.rrset.from_text(
                        qctx.qname,
                        3600,
                        qctx.qclass,
                        dns.rdatatype.A,
                        LOCALADDR,
                    )
                )
            response.set_rcode(dns.rcode.NOERROR)

        elif m := re.match(r"^ns1\.(\d+)\.example\.org$", qname):
            n = int(m.group(1))
            nxt = n + 1
            wait = True
            if self.limit == 0:
                response.authority.append(
                    dns.rrset.from_text(
                        f"{n}.example.org.",
                        86400,
                        qctx.qclass,
                        dns.rdatatype.NS,
                        f"ns1.{nxt}.example.org.",
                    )
                )
            else:
                self.send_response = True
                if qctx.qtype == dns.rdatatype.A:
                    response.answer.append(
                        dns.rrset.from_text(
                            qctx.qname,
                            3600,
                            qctx.qclass,
                            dns.rdatatype.A,
                            LOCALADDR,
                        )
                    )
            response.set_rcode(dns.rcode.NOERROR)

        elif qname == "direct.example.net":
            if qctx.qtype == dns.rdatatype.A:
                response.answer.append(
                    dns.rrset.from_text(
                        qctx.qname,
                        3600,
                        qctx.qclass,
                        dns.rdatatype.A,
                        LOCALADDR,
                    )
                )
            response.set_rcode(dns.rcode.NOERROR)

        elif m := re.match(r"^ns1\.(\d+)\.example\.net$", qname):
            n = int(m.group(1))
            nxt = (n + 1) * 16
            for i in range(1, 16):
                s = nxt + i
                response.authority.append(
                    dns.rrset.from_text(
                        f"{n}.example.net.",
                        86400,
                        qctx.qclass,
                        dns.rdatatype.NS,
                        f"ns1.{s}.example.net.",
                    )
                )
                response.additional.append(
                    dns.rrset.from_text(
                        f"ns1.{s}.example.net.",
                        86400,
                        qctx.qclass,
                        dns.rdatatype.A,
                        "10.53.0.7",
                    )
                )
            response.set_rcode(dns.rcode.NOERROR)

        else:
            response.set_rcode(dns.rcode.NXDOMAIN)

        if wait:
            await self._maybe_delay()

        yield DnsResponseSend(response)


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(RecursionChainHandler())
    server.run()


if __name__ == "__main__":
    main()
