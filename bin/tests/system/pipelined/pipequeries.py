# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# Send A queries for the names read from stdin over a single TCP
# connection, all of them before reading any response, and print the
# answer sections in the order the responses arrive.

import argparse
import socket
import sys
import time

import dns.message
import dns.query
import dns.rcode

SERVER = "10.53.0.4"
TIMEOUT = 30


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--port", type=int, default=5300)
    args = parser.parse_args()

    pending = {}
    for msgid, qname in enumerate(sys.stdin.read().split()):
        query = dns.message.make_query(qname, "A", id=msgid)
        pending[msgid] = query

    expiration = time.time() + TIMEOUT
    with socket.create_connection((SERVER, args.port), timeout=TIMEOUT) as sock:
        for query in pending.values():
            dns.query.send_tcp(sock, query, expiration)

        while pending:
            response, _ = dns.query.receive_tcp(sock, expiration)
            query = pending.pop(response.id, None)
            if query is None or not query.is_response(response):
                sys.exit(f"I:unexpected response:\n{response}")
            if response.rcode() != dns.rcode.NOERROR:
                sys.exit(f"I:response rcode: {dns.rcode.to_text(response.rcode())}")
            if len(response.answer) != 1:
                print(
                    f"I:response answer count ({len(response.answer)}!=1)",
                    file=sys.stderr,
                )
            for rrset in response.answer:
                print(rrset.to_text(), flush=True)


if __name__ == "__main__":
    main()
