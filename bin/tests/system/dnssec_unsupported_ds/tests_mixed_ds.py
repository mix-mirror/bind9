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
import os
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
        "ns*/zones/*.db.in",
        "ns*/zones/*.db.signed",
    ]
)


def modify_dsset():
    with open("ns3/dsset-child.example.", encoding="utf-8") as dsset_file:
        ds_orig = dsset_file.readline()

    alg = Algorithm.default().number
    alg_re = Re(rf"\s+{alg}\s+")
    ds_unsupported = alg_re.sub(" 12 ", ds_orig)

    digest_re = Re(rf"\s+{alg}\s+2\s+.*")
    ds_bogus = digest_re.sub(f" {alg} 2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ds_orig)

    with open("ns3/dsset-child.example.", "w", encoding="utf-8") as dsset_file:
        dsset_file.writelines([ds_unsupported, ds_bogus])


def bootstrap():
    child = Zone("child.example", "child.example.db.signed", Nameserver("ns3", "10.53.0.3"))
    isctest.setup.configure_signed_zone(child, [], template="template.db.j2.manual")

    isctest.log.info("child.example: modify DS set to have unsupported and bogus DS records")
    modify_dsset()

    example = Zone("example", "example.db.signed", Nameserver("ns2", "10.53.0.2"))
    isctest.setup.configure_signed_zone(example, [child], template="template.db.j2.manual")

    ta = isctest.setup.configure_signed_root([example])
    return {
        "trust_anchors": [ta],
        "zones": [child, example],
    }


def test_mixed_ds(ns9):
    msg = isctest.query.create("child.example.", "DNSKEY")
    with ns9.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, ns9.ip)
        watcher.wait_for_line("child.example/DNSKEY: insecurity proof failed")
    isctest.check.servfail(res)

    msg = isctest.query.create("a.child.example.", "A")
    res = isctest.query.tcp(msg, ns9.ip)
    isctest.check.servfail(res)
