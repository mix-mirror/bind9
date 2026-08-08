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

"""Exercise StreamDNS scheduling through attacker-controlled DNS traffic."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import os
import re

import dns.message
import dns.rcode
import dns.rdatatype
import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(["ans*/ans.run"])

COALESCED = "coalescing pending StreamDNS read job"
QUERY_COUNT = int(os.environ.get("STREAMDNS_QUERY_COUNT", "256"))
WORKERS = 64


def _read_log(server) -> str:
    return Path(server.log.path).read_text(encoding="utf-8", errors="replace")


def _query(server, qname: str) -> None:
    query = dns.message.make_query(qname, dns.rdatatype.A)
    response = isctest.query.udp(query, server.ip, timeout=15)
    assert response.rcode() == dns.rcode.NOERROR, response
    assert any(rrset.rdtype == dns.rdatatype.A for rrset in response.answer), response


def _run_mode(server, authority, mode: str) -> int:
    server.rndc("flush")
    server.rndc("trace 1")

    named_before = _read_log(server)
    authority_before = _read_log(authority)
    if mode == "ordinary":
        qnames = ["ordinary.streamdns."] * QUERY_COUNT
    else:
        qnames = [
            f"{server.identifier}-{index}.{mode}.streamdns."
            for index in range(QUERY_COUNT)
        ]

    with ThreadPoolExecutor(max_workers=WORKERS) as executor:
        list(executor.map(lambda qname: _query(server, qname), qnames))

    named_delta = _read_log(server)[len(named_before) :]
    authority_delta = _read_log(authority)[len(authority_before) :]
    coalesced = named_delta.count(COALESCED)
    isctest.log.info(
        "%s/%s coalesced %d pending StreamDNS reads",
        server.identifier,
        mode,
        coalesced,
    )

    if mode in {"tc", "pipeline", "batch", "fragment"}:
        assert f"Received {mode} TCP query" in authority_delta
    if mode in {"pipeline", "batch", "fragment"}:
        groups = [
            int(count)
            for count in re.findall(
                rf"Sending {mode} group containing (\d+) responses",
                authority_delta,
            )
        ]
        assert groups and max(groups) > 1, groups

    return coalesced


def test_remote_streamdns_read_scheduling(servers):
    results = {}
    for resolver_name, authority_name in (("ns1", "ans3"), ("ns2", "ans4")):
        resolver = servers[resolver_name]
        authority = servers[authority_name]
        results[resolver_name] = {
            mode: _run_mode(resolver, authority, mode)
            for mode in (
                "ordinary",
                "plain",
                "tc",
                "pipeline",
                "batch",
                "fragment",
            )
        }

    baseline = sum(
        values[mode] for values in results.values() for mode in ("ordinary", "plain")
    )
    attacker_controlled = sum(
        values[mode]
        for values in results.values()
        for mode in ("tc", "pipeline", "batch", "fragment")
    )
    isctest.log.info(
        "StreamDNS coalescence totals: baseline=%d attacker-controlled=%d",
        baseline,
        attacker_controlled,
    )
    assert baseline == 0, results
