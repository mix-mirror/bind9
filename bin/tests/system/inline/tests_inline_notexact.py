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

import dns.rcode
import dns.update
import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    [
        "K*",
        "*.out*",
        "*/*.out*",
        "ns*/K*",
        "ns*/dsset-*",
        "ns*/*.bk",
        "ns*/*.db",
        "ns*/*.jbk",
        "ns*/*.jnl",
        "ns*/*.nzd",
        "ns*/*.signed",
        "ns*/trusted.conf",
        "ns3/delayedkeys.conf",
        "ns3/removedkeys",
    ]
)


def query_txt(server, qname):
    query = isctest.query.create(qname, "TXT")
    return isctest.query.tcp(query, server.ip)


def txt_exists(server, qname):
    response = query_txt(server, qname)
    return response.rcode() == dns.rcode.NOERROR


def test_inline_journal_apply_failure_recovers(ns3):
    """
    Check that inline signing recovers from an exact-apply failure.

    The raw zone's on-disk journal deletes stale-record.notexact/TXT,
    but the signed zone snapshot does not contain that RRset. Building the
    journal diff succeeds; applying it to the signed database does not. The
    signer must fall back to comparing the raw and signed databases directly.
    """
    zone = "notexact"
    failed_rrset = "stale-record.notexact/TXT/IN"
    apply_error = f"dns_diff_apply: {failed_rrset}: del not exact"

    with ns3.watch_log_from_start() as watcher:
        watcher.wait_for_line(apply_error)

    qname = f"added-record.{zone}."
    isctest.run.retry_with_timeout(
        lambda: txt_exists(ns3, qname),
        timeout=10,
        msg="signed zone did not recover by comparing the databases",
    )

    update = dns.update.UpdateMessage(zone)
    update.add(f"dynamic-record.{zone}.", 300, "TXT", "ABC")
    ns3.nsupdate(update)

    qname = f"dynamic-record.{zone}."
    isctest.run.retry_with_timeout(
        lambda: txt_exists(ns3, qname),
        timeout=10,
        msg="update was not applied to the recovered signed zone",
    )
