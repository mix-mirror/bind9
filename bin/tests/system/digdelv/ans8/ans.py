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

from typing import AsyncGenerator, List, Optional

import dns
import dns.rcode

from isctest.asyncserver import (
    AsyncDnsServer,
    CloseConnection,
    DnsResponseSend,
    DomainHandler,
    QueryContext,
    ResponseAction,
    ResponseDrop,
)


class SilentHandler(DomainHandler):
    """Handler that doesn't respond."""

    domains = ["silent.example"]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        yield ResponseDrop()


class CloseHandler(DomainHandler):
    """Handler that doesn't respond and closes TCP connection."""

    domains = ["close.example"]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        yield CloseConnection()


class ServfailHandler(DomainHandler):
    """Handler that always responds with SERVFAIL."""

    domains = ["servfail.example"]

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        qctx.response.set_rcode(dns.rcode.SERVFAIL)
        yield DnsResponseSend(qctx.response)


class SilentThenServfailHandler(DomainHandler):
    """Handler that drops one query and response to the next one with SERVFAIL."""

    domains = ["silent-then-servfail.example"]
    counter = 0

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        if self.counter % 2 == 0:
            yield ResponseDrop()
        else:
            qctx.response.set_rcode(dns.rcode.SERVFAIL)
            yield DnsResponseSend(qctx.response)
        self.counter += 1


def main() -> None:
    server = AsyncDnsServer()
    server.install_response_handler(SilentHandler())
    server.install_response_handler(CloseHandler())
    server.install_response_handler(ServfailHandler())
    server.install_response_handler(SilentThenServfailHandler())
    server.run()


if __name__ == "__main__":
    main()
