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

import re
import time

import pytest

import isctest

import dns.message

# pylint: disable=unused-import
from xfer.common import (
    validate_axfr_from_query_and_file,
    sendcmd,
    set_ns4_as_secondary_for_nil,
    check_rdata_in_txt_record,
    get_response,
)

# "dns.exception.FormError: invalid AMTRELAY relay type: 22" error is present in dnspython 2.1.0
pytest.importorskip("dns", minversion="2.2.0")


# Initially, ns4 is not authoritative for anything.
# Now that ans is up and running with the right data, we make ns4
# a secondary for nil.
def test_make_ns4_secondary_for_nil(
    set_ns4_as_secondary_for_nil, ns4, named_port
):  # pylint: disable=unused-argument,redefined-outer-name
    # now we test transfers with assorted TSIG glitches.
    # testing that incorrectly signed transfers will fail.

    def wait_for_soa():
        for _ in range(10):
            msg = dns.message.make_query("nil.", "SOA")
            res = isctest.query.tcp(msg, "10.53.0.4")
            if res.rcode() == dns.rcode.NOERROR:
                for rr in res.answer:
                    if rr.rdtype == dns.rdatatype.SOA:
                        return True
            time.sleep(1)
        return False

    sendcmd("goodaxfr")
    with ns4.watch_log_from_here() as watcher_retransfer_nil_success:
        ns4.rndc("retransfer nil.")
        retransfer_nil_pattern = re.compile(
            f"transfer of 'nil/IN' from 10.53.0.5#{named_port}: Transfer status: success"
        )
        watcher_retransfer_nil_success.wait_for_line(retransfer_nil_pattern)
    assert wait_for_soa(), "SOA not found in the response"
    check_rdata_in_txt_record("initial AXFR")


def test_tsig_signed_zone_transfer():
    key = dns.tsig.Key(
        name="tsigzone.",
        secret="1234abcd8765",
        algorithm=isctest.vars.ALL["DEFAULT_HMAC"],
    )
    msg = dns.message.make_query("tsigzone.", "AXFR")
    msg.use_tsig(keyring=key)
    res2 = get_response(msg, "10.53.0.2")
    res3 = get_response(msg, "10.53.0.3")
    isctest.check.rrsets_equal(res2.answer, res3.answer)


# test mapped. zone with out zone data
def test_mapped_zone(named_port, ns3):
    msg_txt = dns.message.make_query("mapped.", "TXT")
    get_response(msg_txt, "10.53.0.3", allow_empty_answer=True)

    ns3.stop()
    ns3.start(["--noclean", "--restart", "--port", str(named_port)])

    get_response(msg_txt, "10.53.0.3", allow_empty_answer=True)

    msg_axfr = dns.message.make_query("mapped.", "AXFR")
    validate_axfr_from_query_and_file(msg_axfr, "10.53.0.3", "knowngood.mapped")
