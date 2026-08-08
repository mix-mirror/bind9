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

"""Authoritative server with controllable UDP-to-TCP response scheduling."""

from collections.abc import AsyncGenerator

import asyncio
import logging

import dns.flags
import dns.message
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    ConnectionHandler,
    DnsResponseSend,
    Peer,
    QueryContext,
    ResponseAction,
    ResponseHandler,
)

ADDRESS = "192.0.2.1"
BATCH_SIZE = 16
FORCE_TCP = {"tc", "pipeline", "batch", "fragment"}


def _mode(message: dns.message.Message) -> str:
    labels = message.question[0].name.to_text().rstrip(".").split(".")
    if len(labels) < 2 or labels[-1] != "streamdns":
        return "plain"
    return labels[-2]


def _answer(query: dns.message.Message) -> dns.message.Message:
    response = dns.message.make_response(query)
    response.flags |= dns.flags.AA
    if query.question[0].rdtype == dns.rdatatype.A:
        response.answer.append(
            dns.rrset.from_text(
                query.question[0].name,
                30,
                dns.rdataclass.IN,
                dns.rdatatype.A,
                ADDRESS,
            )
        )
    return response


def _frame(response: dns.message.Message) -> bytes:
    wire = response.to_wire(max_size=65535)
    return len(wire).to_bytes(2, byteorder="big") + wire


class ControlledUdpHandler(ResponseHandler):
    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        qctx.prepare_new_response(with_zone_data=False)
        mode = _mode(qctx.query)
        if mode in FORCE_TCP:
            qctx.response.flags |= dns.flags.TC
        elif qctx.qtype == dns.rdatatype.A:
            qctx.response.answer.append(
                dns.rrset.from_text(
                    qctx.qname,
                    30,
                    dns.rdataclass.IN,
                    dns.rdatatype.A,
                    ADDRESS,
                )
            )
        yield DnsResponseSend(qctx.response, authoritative=True)


class ControlledTcpHandler(ConnectionHandler):
    async def _send_group(
        self,
        writer: asyncio.StreamWriter,
        mode: str,
        frames: list[bytes],
    ) -> None:
        if not frames:
            return

        logging.info("Sending %s group containing %d responses", mode, len(frames))
        if mode == "pipeline":
            for frame in frames:
                writer.write(frame)
                await writer.drain()
            return

        wire = b"".join(frames)
        if mode == "batch":
            writer.write(wire)
            await writer.drain()
            return

        assert mode == "fragment"
        offset = 0
        chunk_sizes = (1, 1, 2, 3, 5, 8, 13, 21, 34, 55)
        chunk = 0
        while offset < len(wire):
            size = chunk_sizes[chunk % len(chunk_sizes)]
            writer.write(wire[offset : offset + size])
            await writer.drain()
            await asyncio.sleep(0)
            offset += size
            chunk += 1

    async def handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        peer: Peer,
    ) -> None:
        pending: list[bytes] = []
        pending_mode: str | None = None

        while True:
            try:
                if pending:
                    length_wire = await asyncio.wait_for(
                        reader.readexactly(2), timeout=0.02
                    )
                else:
                    length_wire = await reader.readexactly(2)
            except asyncio.TimeoutError:
                assert pending_mode is not None
                await self._send_group(writer, pending_mode, pending)
                pending = []
                pending_mode = None
                continue
            except asyncio.IncompleteReadError:
                if pending:
                    assert pending_mode is not None
                    await self._send_group(writer, pending_mode, pending)
                return

            length = int.from_bytes(length_wire, byteorder="big")
            try:
                wire = await reader.readexactly(length)
            except asyncio.IncompleteReadError:
                return

            query = dns.message.from_wire(wire)
            mode = _mode(query)
            logging.info(
                "Received %s TCP query for %s (ID=%d) from %s",
                mode,
                query.question[0].name,
                query.id,
                peer,
            )
            frame = _frame(_answer(query))

            if mode not in {"pipeline", "batch", "fragment"}:
                writer.write(frame)
                await writer.drain()
                continue

            if pending_mode is not None and pending_mode != mode:
                await self._send_group(writer, pending_mode, pending)
                pending = []

            pending_mode = mode
            pending.append(frame)
            if len(pending) >= BATCH_SIZE:
                await self._send_group(writer, mode, pending)
                pending = []
                pending_mode = None


def main() -> None:
    server = AsyncDnsServer(default_rcode=dns.rcode.NOERROR)
    server.install_response_handler(ControlledUdpHandler())
    server.install_connection_handler(ControlledTcpHandler())
    server.run()
