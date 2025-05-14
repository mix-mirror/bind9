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

import os
import socket
import time

import pytest

import isctest

import dns.message

NEW_SOA_SERIAL = 1397051953
OLD_SOA_SERIAL = 1397051952


def sendcmd(cmdfile):
    host = "10.53.0.5"
    port = int(isctest.vars.ALL["EXTRAPORT1"])
    cmdfile = f"ans5/{cmdfile}"
    assert os.path.exists(cmdfile)

    sock = socket.create_connection((host, port))
    with open(cmdfile, "r", encoding="utf-8") as f:
        for line in f:
            sock.sendall(line.encode())
    sock.close()


def check_rdata_in_txt_record(rdata, should_exist=True):
    msg = dns.message.make_query("nil.", "TXT")

    for _ in range(10):
        res = get_response(msg, "10.53.0.4")
        for rr in res.answer:
            if rr.rdtype == dns.rdatatype.TXT:
                found = rdata in rr.to_text()
                if (found and should_exist) or (not found and not should_exist):
                    return
        time.sleep(1)

    expectation = "found" if should_exist else "not found"
    assert False, f"TXT rdata '{rdata}' {expectation} in the response\n{res}"


def get_response(msg, server_ip, allow_empty_answer=False):
    res = isctest.query.tcp(msg, server_ip)
    isctest.check.noerror(res)
    if not allow_empty_answer:
        assert res.answer != []
    return res


@pytest.fixture(autouse=False, scope="module")
def set_ns4_as_secondary_for_nil(ns4):
    # initial correctly-signed transfer should succeed
    sendcmd("goodaxfr")

    config_block = """
zone "nil" {
    type secondary;
    file "nil.db";
    primaries { 10.53.0.5 key tsig_key; };
};
"""
    with open("ns4/named.conf", "a", encoding="utf-8") as f:
        f.write(config_block)

    with ns4.watch_log_from_here() as watcher:
        ns4.rndc("reload")
        watcher.wait_for_line("Transfer status: success")


def validate_axfr_from_query_and_file(msg, server_ip, golden_file):
    res = get_response(msg, server_ip)
    with open(golden_file, "r", encoding="utf-8") as good_response:
        golden_response = dns.message.from_file(good_response)
        isctest.check.rrsets_equal(golden_response.answer, res.answer)


def validate_axfr_from_query_and_query(msg, server_ip1, server_ip2):
    res1 = get_response(msg, server_ip1)
    res2 = get_response(msg, server_ip2)
    isctest.check.rrsets_equal(res1.answer, res2.answer)


def check_soa_serial_with_retry(checked_zone, recovery_function):
    def get_soa_serial(qname, server_ip, serial):
        msg = dns.message.make_query(qname, "SOA")
        res = get_response(msg, server_ip)
        for rr in res.answer:
            if rr.rdtype == dns.rdatatype.SOA and rr[0].serial == serial:
                isctest.log.debug(f"SOA serial {serial} found in the response")
                return True
        return False

    for _ in range(20):
        serial_found_in_responses = 0
        for server, zone in checked_zone:
            if get_soa_serial(zone, server, NEW_SOA_SERIAL):
                serial_found_in_responses += 1
        if serial_found_in_responses == len(checked_zone):
            return
        recovery_function()

    assert False, f"SOA serial {NEW_SOA_SERIAL} not found in responses"
