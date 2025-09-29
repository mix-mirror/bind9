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

import time


import dns
import dns.update
import pytest
import isctest


def add_catz_rr(ns, catz, domain):
    update_msg = dns.update.UpdateMessage(catz)
    update_msg.add(f"{domain}zones.{catz}", 300, "PTR", domain)
    ns.nsupdate(update_msg)


def test_addparser(ns1, ns2, ns3):
    for n in range(1000):
        ns1.rndc(f"addzone somedomain-1-{n}. {{type primary; file \"somedomain.db\";}};")
        add_catz_rr(ns1, "catalog1.example.", f"somedomain-1-{n}.")
        
        ns2.rndc(f"addzone somedomain-2-{n}. {{type primary; file \"somedomain.db\";}};")
        add_catz_rr(ns2, "catalog2.example.", f"somedomain-2-{n}.")

        ns3.rndc(f"addzone somedomain-3-{n}. {{type primary; file \"somedomain.db\";}};")
        add_catz_rr(ns3, "catalog3.example.", f"somedomain-3-{n}.")

    msg = dns.message.make_query("ns.somedomain-1-999.", "A")
    res = isctest.query.udp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    assert len(res.answer) == 1
    assert res.answer[0] == dns.rrset.from_text("ns.somedomain-1-999.", 120, "IN", "A", "10.53.6.66")
    
    msg = dns.message.make_query("ns.somedomain-2-999.", "A")
    res = isctest.query.udp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    assert len(res.answer) == 1
    assert res.answer[0] == dns.rrset.from_text("ns.somedomain-2-999.", 120, "IN", "A", "10.53.6.66")

    msg = dns.message.make_query("ns.somedomain-3-999.", "A")
    res = isctest.query.udp(msg, "10.53.0.4")
    isctest.check.noerror(res)
    assert len(res.answer) == 1
    assert res.answer[0] == dns.rrset.from_text("ns.somedomain-3-999.", 120, "IN", "A", "10.53.6.66")



    
