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

from isctest.asyncserver import (
    AsyncDnsServer,
    ResponseHandler,
    QueryContext,
    DnsResponseSend,
    AsyncGenerator,
    ResponseDrop,
    ResponseAction,
)


class NameserverActionInQnameHandler(ResponseHandler):
    """
    Select how to handle respose based on the leftmost qname label.

    Three actions are supported: drop, delay, reply. The action can be based on
    the nameserver identification, e.g. "ns3", or as a "default" action that
    applies if nameserver-specific instruction is missing.

    Actions:
        - `reply`: respond immediately
        - `delay-NNN`: delay the response by NNN ms (NNN is integer)
        - `drop`: ignore the query, don't send any reply

    Nameserver actions are defined with the following syntax:
    nsX-ACTION[-OPTION]
    where
        - `nsX` is the nameserver, `X` is its number
        - `ACTION` is `reply`, `delay` or `drop`
        - `OPTION` is an additional argument, currently only used for `delay` action

    Examples of nameserver actions:
        - `ns3-reply`: instructs `ns3` to answer immediately
        - `ns4-drop`: instructs `ns4` to ignore query
        - `ns5-delay-100`: instructs `ns5` to delay answers by 100 ms

    Finally, multiple nameservers can have actions assigned in a single query.
    Nameserver actions are separated by `_`, e.g.:
        - `ns3-delay-100_ns4-reply`: instructs ns3 to delay replies by 100 ms,
           ns4 to reply immediately
        - `ns5-reply_ns8-delay-500_default-drop`: instrcuts ns5 to reply
          immediately, ns8 to delay replays by 500 ms and all other nameservers
          to ignore the queries
        - `ns9-reply_ns8-delay-800_default-delay-1000`: instructs ns9 to reply
          immediately, ns8 to delay replies by 800 ms and other nameserver to
          delay replies by 1000 ms

    If a default nameserver action is missing and no instruction matching the
    responding nameserver is specified, it is `reply` by default.
    """

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
            logging.info(f"action for ns{self.num} not specified -> reply")
            action_args = ["reply"]

        action = action_args[0]
        assert action in ["drop", "reply", "delay"]
        if action == "drop":
            yield ResponseDrop()
            return

        if qctx.qtype == dns.rdatatype.TXT:
            qctx.response = dns.message.make_response(qctx.query)
            txt = f"ns{self.num} {' '.join(action_args)}"
            txt_rrset = dns.rrset.from_text(
                qctx.qname, 300, dns.rdataclass.IN, dns.rdatatype.TXT, f'"{txt}"'
            )
            qctx.response.answer.append(txt_rrset)
            qctx.response.set_rcode(dns.rcode.NOERROR)
        # elif qctx.qtype == dns.rdatatype.NS:
        #     if qctx.qname.is_subdomain(dns.name.from_text("double-ns")):
        #         first_ns = 3
        #         last_ns = 4
        #     elif qctx.qname.is_subdomain(dns.name.from_text("multiple-ns.")):
        #         first_ns = 3
        #         last_ns = 9
        #     else:
        #         assert False, f"unhandled domain: {qctx.qname}"

        #     for num in range(first_ns, last_ns + 1):
        #         ns_name = f"ns{num}.nsset."
        #         ns_rrset = dns.rrset.from_text(
        #             qctx.qname, 300, dns.rdataclass.IN, dns.rdatatype.NS, ns_name
        #         )
        #         qctx.response.answer.append(ns_rrset)


        delay = 0.0
        if action == "delay":
            if len(action_args) < 2:
                delay = 0.1
            else:
                delay = int(action_args[1]) / 1000.0

        yield DnsResponseSend(qctx.response, delay=delay, authoritative=True)


def delay_server() -> AsyncDnsServer:
    server = AsyncDnsServer()
    server.install_response_handler(NameserverActionInQnameHandler(server.num))
    return server
