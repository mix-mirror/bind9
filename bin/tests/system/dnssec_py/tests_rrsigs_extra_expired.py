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

from re import compile as Re

import dns
import time
import pytest

import isctest
from isctest.vars.algorithms import Algorithm
from isctest.template import Zone, Nameserver

pytestmark = pytest.mark.extra_artifacts(
    [
        "ns*/dsset-*",
        "ns*/keys",
        "ns*/keys/*.key",
        "ns*/keys/*.private",
        "ns*/trusted.conf",
        "ns*/zones/*.db",
        "ns*/zones/*.db.signed",
    ]
)


def bootstrap():
    zdata = Zone(
        "rrsigs-extra-expired",
        "rrsigs-extra-expired.db.signed",
        Nameserver("ns2", "10.53.0.2"),
    )

    ksk = isctest.setup.generate_key(zdata, "-f KSK")
    zsk = isctest.setup.generate_key(zdata)
    keys = [ksk, zsk]

    isctest.setup.render_zone(zdata, [], keys=keys, template="template.db.j2.manual")

    # create valid but expired signatures
    expired_rdata = set()
    now = int(time.time())
    start = now - 20000
    end = now - 10000
    for i in range(2):
        isctest.setup.sign_zone(zdata, f"-s {start - i} -e {end - i}")
        expired = dns.zone.from_file(
            "ns2/zones/rrsigs-extra-expired.db.signed", origin="rrsigs-extra-expired."
        )
        rdataset = expired.get_rdataset("a", "RRSIG", "A")
        expired_rdata.add(rdataset.pop())

    # sign zone with valid sigs
    isctest.setup.sign_zone(zdata)
    valid = dns.zone.from_file(
        "ns2/zones/rrsigs-extra-expired.db.signed", origin="rrsigs-extra-expired."
    )
    rdataset = valid.find_rdataset("a", "RRSIG", "A")

    # add the expired RRSIGs for a.rrsigs-extra-expired
    for rd in expired_rdata:
        rdataset.add(rd)
    valid.to_file("ns2/zones/rrsigs-extra-expired.db.signed")

    ta = isctest.setup.configure_signed_root([zdata])
    return {
        "max_validations_per_fetch": 2,
        "trust_anchors": [ta],
        "zones": [zdata],
    }


@pytest.fixture(scope="module", autouse=True)
def after_servers_start(ns2):
    msg = isctest.query.create("a.rrsigs-extra-expired", "A")

    # Check the order of returned RRSIGs from auth. Due to rrset-order none;
    # this should remain constant for the remainder of the test.
    # Ensure the first two RRSIGs are expired, otherwise skip the test.
    res = isctest.query.tcp(msg, ns2.ip)
    rrsigs = res.get_rrset(
        res.answer,
        dns.name.from_text("a.rrsigs-extra-expired."),
        dns.rdataclass.IN,
        dns.rdatatype.RRSIG,
        dns.rdatatype.A,
    )
    now = time.time()
    assert len(rrsigs) > 2
    if rrsigs[0].expiration >= now or rrsigs[1].expiration >= now:
        pytest.skip("valid RRSIG listed first in response, re-run test")


def test_regular_query(ns9):
    # sanity check - record with no extra sigs gets NOERROR
    msg = isctest.query.create("b.rrsigs-extra-expired", "A")
    res = isctest.query.tcp(msg, ns9.ip)
    isctest.check.noerror(res)


def test_extra_expired_rrsigs(ns9):
    msg = isctest.query.create("a.rrsigs-extra-expired", "A")
    with ns9.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, ns9.ip)
        watcher.wait_for_sequence(
            [
                Re(r"a.rrsigs-extra-expired/A: verify failed.* RRSIG has expired"),
                Re(r"a.rrsigs-extra-expired/A: maximum number of validations exceeded"),
            ]
        )
    isctest.check.servfail(res)
