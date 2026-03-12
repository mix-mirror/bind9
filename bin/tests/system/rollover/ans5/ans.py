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

import os

import dns

import isctest

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    QueryContext,
    ResponseHandler,
)

DSTTL = 3600
PARENT = "10.53.0.2"
CHILD = "10.53.0.3"
RESOLVER = "10.53.0.4"
PORT = int(os.environ.get("PORT", 5300))


def log_query(qctx: QueryContext) -> None:
    """
    Log a received DNS query to a text file.
    """
    qname = qctx.qname.to_text()
    qtype = dns.rdatatype.to_text(qctx.qtype)
    with open("query.log", "a", encoding="utf-8") as query_log:
        print(f"{qtype} {qname}", file=query_log)


class NotifyHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:

        log_query(qctx)

        if qctx.qtype == dns.rdatatype.CDS:
            # query CDS
            qname = qctx.qname
            query = dns.message.make_query(qname, "CDS", use_edns=True, want_dnssec=True)
            response = isctest.query.tcp(query, CHILD, log_query=False, log_response=False)

            # nsupdate
            tld = qname.to_text().split('.')[-2]
            print(f"Send dynamic update for {tld} to {PARENT}")
            update_msg = dns.update.UpdateMessage(f"{tld}")
            update_msg.delete(f"{qname}", "DS")
            for rrset in response.answer:
                for rr in rrset:
                    rdata = rr.to_text()
                    if rrset.rdtype == dns.rdatatype.CDS:
                        if rdata == "0 0 0 00":
                            break
                        print(f"+{qname} DS {rdata}")
                        update_msg.add(qname, DSTTL, "DS", rdata)

            try:
                response = isctest.query.udp(update_msg, PARENT, log_query=False, log_response=False)
            except dns.exception.Timeout as exc:
                msg = f"update timeout for '{tld}'"
                raise dns.exception.Timeout(msg) from exc

        yield DnsResponseSend(qctx.response, authoritative=True)


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        NotifyHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
