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

"""
Send DNS queries over UDP without waiting for the replies.

Read "name type" lines from a file or stdin and fire one query per
line at the server, all from the same source port; the replies are
never read.  This is how a test bursts a resolver with queries, e.g.
to drive it into its fetch limits.
"""

from collections.abc import Callable, Iterable, Iterator

import argparse
import fileinput
import socket

import dns.entropy
import dns.inet
import dns.message


def random_ids() -> Iterator[int]:
    while True:
        yield dns.entropy.random_16()


def random_without_replacement() -> Iterator[int]:
    used_ids: set[int] = set()
    for query_id in random_ids():
        if query_id not in used_ids:
            used_ids.add(query_id)
            yield query_id
            if len(used_ids) == 65536:
                raise ValueError("DNS transaction IDs exhausted")


def send_queries(
    lines: Iterable[str],
    address: str,
    port: int,
    source_port: int = 0,
    *,
    generator: Callable[[], Iterator[int]] = random_ids,
) -> int:
    """
    Send one recursive query per "name type" line to address:port over
    UDP without reading any replies.  Blank lines and lines starting
    with "#" are skipped.  Return the number of queries sent.
    """
    name_and_rdtype = [
        fields[:2]
        for line in lines
        if (fields := line.split()) and not fields[0].startswith("#")
    ]
    family = dns.inet.af_for_address(address)
    sent = 0
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.bind(("", source_port))
        for (name, rdtype), query_id in zip(name_and_rdtype, generator()):
            query = dns.message.make_query(name, rdtype, id=query_id)
            sock.sendto(query.to_wire(), (address, port))
            sent += 1
    return sent


def main() -> None:
    parser = argparse.ArgumentParser(prog="ditch", description=__doc__)
    parser.add_argument(
        "-s",
        "--server",
        default="127.0.0.1",
        help="server address (default: %(default)s)",
    )
    parser.add_argument(
        "-p", "--port", type=int, default=53, help="server port (default: %(default)s)"
    )
    parser.add_argument(
        "-b",
        "--source-port",
        type=int,
        default=0,
        help="source port to send from (default: any)",
    )
    parser.add_argument(
        "--unique", action="store_true", help="use a distinct random ID for each query"
    )
    parser.add_argument(
        "file",
        nargs="?",
        default="-",
        help="file with one 'name type' query per line (default: stdin)",
    )
    args = parser.parse_args()
    with fileinput.input(files=args.file, encoding="utf-8") as lines:
        send_queries(
            lines,
            args.server,
            args.port,
            args.source_port,
            generator=random_without_replacement if args.unique else random_ids,
        )


if __name__ == "__main__":
    main()
