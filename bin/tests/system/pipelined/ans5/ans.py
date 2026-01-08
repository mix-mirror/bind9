"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from typing import Dict, Tuple

import asyncio
import logging

from isctest.asyncserver import AsyncServer


class DelayedDnsForwarder(AsyncServer):
    def __init__(self, upstream_ip: str, delay: float):
        super().__init__(self._handle_udp, None, "ans.pid")
        self._upstream_ip = upstream_ip
        self._delay = delay
        self._qid_mapping: Dict[int, Tuple[str, int]] = {}

    async def _handle_udp(
        self, wire: bytes, addr: Tuple[str, int], transport: asyncio.DatagramTransport
    ) -> None:
        qid = int.from_bytes(wire[:2], byteorder="big")

        if addr == (self._upstream_ip, self._port):
            # Response from upstream to client
            client_peer = self._qid_mapping.pop(qid, None)
            if client_peer is None:
                raise RuntimeError(
                    f"Unknown query ID {qid} in response from upstream {addr}"
                )
            logging.info(
                "Forwarding response id=%d from %s:%d to %s:%d",
                qid,
                addr[0],
                addr[1],
                client_peer[0],
                client_peer[1],
            )
            transport.sendto(wire, client_peer)
        else:
            # Query from client to upstream
            self._qid_mapping[qid] = addr
            logging.info(
                "Forwarding query id=%d from %s:%d to %s:%d after %.3fs",
                qid,
                addr[0],
                addr[1],
                self._upstream_ip,
                self._port,
                self._delay,
            )
            await asyncio.sleep(self._delay)
            transport.sendto(wire, (self._upstream_ip, self._port))

    async def _handle_tcp(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        raise RuntimeError("TCP should not be used in the pipelined test")


def main():
    DelayedDnsForwarder("10.53.0.2", delay=0.5).run()


if __name__ == "__main__":
    main()
