#!/usr/bin/python3

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
import isctest.log
import isctest.mark
import isctest.run
import isctest.vars

pytest.importorskip("dns")
import dns.message

pytestmark = [
    isctest.mark.with_dnstap,
]


def test_tcponly(ns2, templates):
    templates.render("ns2/named.conf", {"dnstap_supported": True})
    ns2.reconfigure()
    msg = dns.message.make_query("foo.tcp-only.", "A")
    res = isctest.query.udp(msg, "10.53.0.2")
    isctest.check.noerror(res)

    ns2.rndc("dnstap -roll")
    dnstap = isctest.run.EnvCmd("DNSTAPREAD", "ns2/dnstap.log.0")
    isctest.log.info(dnstap("").out.strip())
