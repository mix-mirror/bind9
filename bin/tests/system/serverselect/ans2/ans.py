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

import logging
from typing import Optional, List

import dns
import dns.rcode
import dns.rdatatype
import dns.message

from isctest.asyncserver import (
    AsyncDnsServer,
    ResponseHandler,
    QueryContext,
    DnsResponseSend,
    AsyncGenerator,
    ResponseDrop,
    ResponseAction,
)


class DelayHandler(ResponseHandler):

    def __init__(self, delay: int) -> None:
        self.delay = delay / 1000.

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        yield DnsResponseSend(qctx.response, delay=self.delay, authoritative=True)


def main():
    server = AsyncDnsServer()
    with open("delay", "r", encoding="utf-8") as f:
        delay = int(f.read().strip())
    server.install_response_handler(DelayHandler(delay))
    server.run()


if __name__ == "__main__":
    main()
