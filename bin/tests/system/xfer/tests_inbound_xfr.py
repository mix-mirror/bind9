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

import pytest

import isctest

import dns.message


# dns.query.inbound_xfr() is new in dnspython 2.1.0
# "UnboundLocalError: cannot access local variable 'serial' where it is not associated with a value" error is fixed in dnspython 2.2.0
pytest.importorskip("dns", minversion="2.2.0")


def test_multi_message_uncompressable_zone_transfers(named_port):
    # check that a multi-message uncompressable zone transfers

    zone = dns.zone.Zone(".")
    # Initiate a zone transfer from the server
    dns.query.inbound_xfr("10.53.0.4", zone, port=named_port, timeout=10, lifetime=10)

    for name, node in zone.nodes.items():
        label = name.to_text()
        fqdn = name.derelativize(zone.origin).to_text()

        for rdataset in node.rdatasets:
            rtype = dns.rdatatype.to_text(rdataset.rdtype)
            for rdata in rdataset:
                if rtype == "A":
                    # The A records name is either "." or in the format "xN",
                    # where N is a number between 0 and 9999
                    assert fqdn == "." or (
                        label.startswith("x")
                        and label[1:].isdigit()
                        and 0 <= int(label[1:]) < 10000
                    )
                elif rtype in ("SOA", "NS"):
                    assert fqdn == "."
                else:
                    assert (
                        False
                    ), f"Unexpected RRset: {fqdn} {rdataset.ttl} IN {rtype} {rdata}"


# test small transfer TCP message size (transfer-message-size 1024;)
def test_tcp_message_compression_makes_difference(named_port):
    key = dns.tsig.Key(
        name="key1.",
        secret="1234abcd8765",
        algorithm=isctest.vars.ALL["DEFAULT_HMAC"],
    )
    msg = dns.message.make_query("example.", "AXFR")
    msg.use_tsig(keyring=key)
    zone = dns.zone.Zone("example.")
    dns.query.inbound_xfr(
        "10.53.0.8", zone, query=msg, port=named_port, timeout=10, lifetime=10
    )

    xfr_size = 0
    for name, node in zone.nodes.items():
        fqdn = name.derelativize(zone.origin).to_text()
        for rdataset in node.rdatasets:
            xfr_size += len(f"{fqdn} {rdataset}")
    assert xfr_size >= 452172, f"XFR size {xfr_size} seems too small"

    tcp_messages_sent = 0
    with open("ns8/named.run", "r", encoding="utf-8") as file:
        for line in file:
            if "sending TCP message of" in line:
                tcp_messages_sent += 1
    assert tcp_messages_sent > 300, f"Too few TCP messages sent: {tcp_messages_sent}"
