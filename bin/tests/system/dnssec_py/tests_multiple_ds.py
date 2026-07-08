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

from dns.dnssec import DSDigest

from dnssec_py.common import DNSSEC_PY_MARK
from isctest.algorithms import Algorithm
from isctest.template import NS2, NS3, zones
from isctest.zone import Zone, configure_root

import isctest

pytestmark = DNSSEC_PY_MARK


def multiply_dsset():
    with open("ns3/dsset-child-multiple.multiple-ds.", encoding="utf-8") as dsset_file:
        ds_orig = dsset_file.readline()

    ds_unsupported_list = []

    # Wreck the DNSKEY algorithm.
    alg = Algorithm.default().number
    alg_re = Re(rf"\s+{alg}\s+")
    for i in range(0, 5):
        ds_unsupported_list.append(alg_re.sub(f" {25+i} ", ds_orig))

    # Wrek the DS digest, the digest used by `Zone()` is SHA256.
    digest = DSDigest.SHA256
    digest_re = Re(rf"\s+{digest}\s+")
    for i in range(0, 5):
        ds_unsupported_list.append(digest_re.sub(f" {25+i} ", ds_orig))

    with open(
        "ns3/dsset-child-multiple.multiple-ds.", "w", encoding="utf-8"
    ) as dsset_file:
        dsset_file.writelines(ds_unsupported_list)


def invalidate_dsset_alg():
    with open("ns3/dsset-child-single.multiple-ds.", encoding="utf-8") as dsset_file:
        ds_orig = dsset_file.readline()

    alg = Algorithm.default().number
    alg_re = Re(rf"\s+{alg}\s+")

    with open(
        "ns3/dsset-child-single.multiple-ds.", "w", encoding="utf-8"
    ) as dsset_file:
        dsset_file.writelines([alg_re.sub(" 0 ", ds_orig)])


def bootstrap():
    child_multiple = Zone("child-multiple.multiple-ds", NS3, signed=True)
    child_multiple.configure()
    multiply_dsset()

    child_single = Zone("child-single.multiple-ds", NS3, signed=True)
    child_single.configure()
    invalidate_dsset_alg()

    multiple_ds = Zone("multiple-ds", NS2, signed=True)
    multiple_ds.delegations = [child_multiple, child_single]
    multiple_ds.configure()

    root = configure_root([multiple_ds])

    return {
        "trust_anchors": root.trust_anchors(),
        "zones": zones([root, multiple_ds, child_multiple, child_single]),
    }


def test_multiple_invalid_ds(ns9):
    msg = isctest.query.create("a.child-multiple.multiple-ds.", "A")
    with ns9.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, ns9.ip)
        watcher.wait_for_line(
            "validating child-multiple.multiple-ds/DNSKEY: too many invalid/unsuported DS"
        )
    isctest.check.servfail(res)


# A DS which its DNSKEY uses algorithm 0 is invalid, but ensure there is no attempts in the code to assert
# that `val->unsupported_algorithm != 0` when there is no more DS key to try to validate.
def test_single_invalid_ds(ns9):
    msg = isctest.query.create("a.child-single.multiple-ds.", "A")
    with ns9.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, ns9.ip)
        watcher.wait_for_line(
            "validating child-single.multiple-ds/DNSKEY: no supported algorithm/digest (DS)"
        )
    isctest.check.noerror(res)
