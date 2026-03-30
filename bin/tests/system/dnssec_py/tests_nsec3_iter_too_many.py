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
    sub = Zone("sub.nsec3-iter-too-many", "sub.nsec3-iter-too-many.db.signed", Nameserver("ns3", "10.53.0.3"))
    isctest.setup.configure_signed_zone(sub, [], template="template.db.j2.manual")

    parent = Zone("nsec3-iter-too-many", "nsec3-iter-too-many.db.signed", Nameserver("ns2", "10.53.0.2"))

    ksk = isctest.setup.generate_key(parent, "-f KSK")
    zsk = isctest.setup.generate_key(parent)
    keys = [ksk, zsk]

    isctest.setup.render_zone(parent, [sub], keys, template="template.db.j2.manual")
    isctest.setup.sign_zone(parent, "-3 A1B2C3D4 -H too-many -H 51")

    ta = isctest.setup.configure_signed_root([parent])

    return {
        "trust_anchors": [ta],
        "zones": [sub, parent],
    }


def test_excessive_nsec3_iterations_delegation(ns9):
    # reproducer for CVE-2026-1519 [GL#5708]
    zone = "a.sub.nsec3-iter-too-many"
    msg = isctest.query.create(zone, "A")
    res = isctest.query.tcp(msg, ns9.ip)

    # an insecure response is expected regardless of the NSEC3 iteration limit,
    # because the sub.nsec3-iter-too-many. zone is unsigned. the real
    # difference is in the CPU usage required for generating such response, but
    # that can't be easily and reliably tested in an automated fashion
    isctest.check.noerror(res)

    with ns9.watch_log_from_start() as watcher:
        watcher.wait_for_line(
            f"validating {zone}/A: validator_callback_ds: too many iterations"
        )
