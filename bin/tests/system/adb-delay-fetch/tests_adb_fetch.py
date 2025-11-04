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
from isctest.util import param


@pytest.fixture(autouse=True)
def flush(ns2):
    ns2.rndc("flush")


@pytest.mark.parametrize("qname, expected_ns", [
    param("ns3-reply_default-drop.double-ns.", "ns3"),
    param("ns4-reply_default-drop.double-ns.", "ns4"),
    param("ns3-reply_ns4-delay-500.double-ns.", "ns3"),
    param("ns3-delay-500_ns4-reply.double-ns.", "ns4"),
    param("ns3-delay-800_ns4-delay-200.double-ns.", "ns4"),
    param("ns3-reply_default-drop.multiple-ns.", "ns3"),
    param("ns4-reply_default-drop.multiple-ns.", "ns4"),
    param("ns5-reply_default-drop.multiple-ns.", "ns5"),
    param("ns6-reply_default-drop.multiple-ns.", "ns6"),
    param("ns7-reply_default-drop.multiple-ns.", "ns7"),
    # param("ns8-reply_default-drop.multiple-ns.", "ns8"),
    # param("ns9-reply_default-drop.multiple-ns.", "ns9"),
    # param("ns3-delay-1000_ns4-delay-800_ns5-delay-600_default-reply.multiple-ns.", "ns6"),
    # param("ns3-delay-1000_ns4-delay-800_ns5-delay-600_ns6-delay-400_ns7-delay-200_default-reply.multiple-ns.", "ns8"),
])
def test_adb_fetch_cold_cache(qname, expected_ns):
    isctest.log.info(f"sending query for {qname}")
    msg = isctest.query.create(qname, "TXT")
    res = isctest.query.tcp(msg, "10.53.0.2")

    isctest.log.info("check we got a reply")
    isctest.check.noerror(res)

    isctest.log.info(f"check the reply originated from {expected_ns}")
    text = res.answer[0][0].strings[0].decode('ascii')
    ns = text.split()[0]
    assert expected_ns == ns, f"expected answer to come from {expected_ns}, but it came from {ns}"
