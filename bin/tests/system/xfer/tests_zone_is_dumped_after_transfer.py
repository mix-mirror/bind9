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

import fileinput
import os
import time

import pytest


import dns.message

from xfer.common import (
    validate_axfr_from_query_and_file,
    OLD_SOA_SERIAL,
    NEW_SOA_SERIAL,
    get_response,
    check_soa_serial_with_retry,
    validate_axfr_from_query_and_query,
)

# "dns.exception.FormError: invalid AMTRELAY relay type: 22" error is present in dnspython 2.1.0
pytest.importorskip("dns", minversion="2.2.0")


def test_zone_is_dumped_after_transfer(ns1, ns2, ns3, ns6, ns7):
    def rndc_reload(*servers):
        for server in servers:
            server.rndc("reload")

    # reload servers for preparation of ixfr-from-differences tests
    rndc_reload(ns1, ns2, ns3, ns6, ns7)

    # basic zone transfer
    msg = dns.message.make_query("example.", "AXFR")
    validate_axfr_from_query_and_file(msg, "10.53.0.2", "response1.good")
    validate_axfr_from_query_and_file(msg, "10.53.0.3", "response1.good")

    # update primary zones for ixfr-from-differences tests
    for zone_file in [
        "ns1/sec.db",
        "ns2/example.db",
        "ns6/primary.db",
        "ns7/primary2.db",
    ]:
        with fileinput.FileInput(zone_file, inplace=True) as file:
            for line in file:
                print(
                    line.replace(" 0.0.0.0", " 0.0.0.1").replace(
                        str(OLD_SOA_SERIAL), str(NEW_SOA_SERIAL)
                    ),
                    end="",
                )
    rndc_reload(ns1, ns2, ns6, ns7)

    msg = dns.message.make_query("secondary.", "SOA")
    res = get_response(msg, "10.53.0.2")
    for rr in res.answer:
        if rr.rdtype == dns.rdatatype.SOA:
            assert rr[0].serial == OLD_SOA_SERIAL
            break
    else:
        assert False, f"SOA serial {OLD_SOA_SERIAL} not found in the response"

    # wait for reloads
    reloaded_zones = (
        ("10.53.0.6", "primary."),
        ("10.53.0.1", "secondary."),
        ("10.53.0.2", "example."),
    )
    check_soa_serial_with_retry(reloaded_zones, lambda: time.sleep(1))

    def notify_some_servers():
        ns6.rndc("notify primary.")
        ns1.rndc("notify secondary.")
        ns2.rndc("notify example.")
        time.sleep(2)

    # wait for transfers
    transfered_zones = (
        ("10.53.0.3", "example."),
        ("10.53.0.3", "primary."),
        ("10.53.0.6", "secondary."),
    )
    check_soa_serial_with_retry(transfered_zones, notify_some_servers)

    msg = dns.message.make_query("example.", "AXFR")
    validate_axfr_from_query_and_file(msg, "10.53.0.3", "response2.good")

    # ns3 has a journal iff it received an IXFR.
    assert os.path.exists("ns3/example.bk")
    assert os.path.exists("ns3/example.bk.jnl")

    # testing ixfr-from-differences primary; (primary zone)
    msg = dns.message.make_query("primary.", "AXFR")
    validate_axfr_from_query_and_query(msg, "10.53.0.6", "10.53.0.3")

    # ns3 has a journal iff it received an IXFR.
    assert os.path.exists("ns3/primary.bk")
    assert os.path.exists("ns3/primary.bk.jnl")

    # testing ixfr-from-differences primary; (secondary zone)
    msg = dns.message.make_query("secondary.", "AXFR")
    validate_axfr_from_query_and_query(msg, "10.53.0.6", "10.53.0.1")

    # ns6 has a journal iff it received an IXFR.
    assert os.path.exists("ns6/sec.bk")
    assert not os.path.exists("ns6/sec.bk.jnl")

    # testing ixfr-from-differences secondary; (secondary zone)

    # ns7 has a journal iff it generates an IXFR.
    assert os.path.exists("ns7/primary2.db")
    assert not os.path.exists("ns7/primary2.db.jnl")

    # testing ixfr-from-differences secondary; (secondary zone)

    msg = dns.message.make_query("secondary.", "AXFR")
    validate_axfr_from_query_and_query(msg, "10.53.0.1", "10.53.0.7")

    # ns7 has a journal iff it generates an IXFR.
    assert os.path.exists("ns7/sec.bk")
    assert os.path.exists("ns7/sec.bk.jnl")
