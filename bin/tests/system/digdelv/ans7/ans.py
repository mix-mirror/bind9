# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0.  If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

from typing import AsyncGenerator

import dns
import dns.flags
import dns.update

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    ResponseHandler,
    QueryContext,
)


class ReplyUpdate(ResponseHandler):

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response = dns.update.UpdateMessage(qctx.qname, id=qctx.query.id)
        qctx.response.flags |= dns.flags.QR
        qctx.response.delete(qctx.qname, dns.rdatatype.SOA)

        yield DnsResponseSend(qctx.response, authoritative=True)


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handler(ReplyUpdate())
    server.run()


if __name__ == "__main__":
    main()
