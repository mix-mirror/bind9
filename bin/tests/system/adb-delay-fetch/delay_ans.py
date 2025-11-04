"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

import logging
from typing import Optional, List

import dns
import dns.rcode
import dns.rdatatype
import dns.message

from isctest.asyncserver import AsyncDnsServer, ResponseHandler, QueryContext, DnsResponseSend, AsyncGenerator, ResponseDrop, ResponseAction


class NameserverActionInQnameHandler(ResponseHandler):
    num: int

    def __init__(self, num: int) -> None:
        super().__init__()
        self.num = num

    def _parse_ns_action(self, actions_str: str) -> Optional[List[str]]:
        default_action = None
        for action_str in actions_str.split("_"):
            action_def = action_str.split("-")
            if len(action_def) == 0:
                continue
            if action_def[0] == f"ns{self.num}":
                return action_def[1:]
            if action_def[0] == "default":
                default_action = action_def[1:]
        return default_action

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[ResponseAction, None]:
        action_str = qctx.qname.labels[0].decode("ascii")
        action_args = self._parse_ns_action(action_str)
        if action_args is None:
            logging.info(f"action for ns{self.num} not specified -> drop")
            yield ResponseDrop()
            return

        assert action_args is not None  # typing
        action = action_args[0]
        if action == "drop":
            yield ResponseDrop()
            return
        if action not in ["reply", "delay"]:
            logging.error(f"unknown action '{action}' for {qctx.qname} -> drop")
            yield ResponseDrop()
            return

        if qctx.qtype == dns.rdatatype.TXT:
            qctx.response = dns.message.make_response(qctx.query)
            txt = f"ns{self.num} {' '.join(action_args)}"
            txt_rrset = dns.rrset.from_text(qctx.qname, 300, dns.rdataclass.IN, dns.rdatatype.TXT, f'"{txt}"')
            qctx.response.answer.append(txt_rrset)
        elif qctx.qtype == dns.rdatatype.NS:
            ns_name = f"ns{self.num}.nsset."
            ns_rrset = dns.rrset.from_text(qctx.qname, 300, dns.rdataclass.IN, dns.rdatatype.NS, ns_name)
            qctx.response.answer.append(ns_rrset)
            a_rrset = dns.rrset.from_text(ns_name, 300, dns.rdataclass.IN, dns.rdatatype.A, f"10.53.0.{self.num}")
            # TODO AAAA?
            qctx.response.authority.append(a_rrset)

        qctx.response.set_rcode(dns.rcode.NOERROR)

        delay = 0.
        if action == "delay":
            if len(action_args) < 2:
                delay = 0.1
            else:
                delay = int(action_args[1]) / 1000.

        yield DnsResponseSend(qctx.response, delay=delay, authoritative=True)


def delay_server() -> AsyncDnsServer:
    server = AsyncDnsServer()
    server.install_response_handler(NameserverActionInQnameHandler(server.num))
    return server
