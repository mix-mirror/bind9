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

import pytest

import isctest
from isctest.template import Nameserver, TrustAnchor, Zone

pytestmark = pytest.mark.extra_artifacts(
    [
        "ns*/trusted.conf",
    ]
)


def bootstrap():
    truncated_selfsigned = Zone(
        "truncated.selfsigned",
        "truncated.selfsigned.db.signed",
        Nameserver("ns2", "10.53.0.2"),
    )

    # The key tag in the trust anchor must match that of the revoked
    # truncated self-signed key in the truncated.selfsigned. zone.
    # The DNSKEY contents are intentionally different here, because the
    # key doesn't have the revoked bit here and that flag is part of the
    # key tag. The following decodes to key tag 33167, which is the same
    # as the revoked truncated key in the zone file.
    ta = TrustAnchor("truncated.selfsigned.", "static-key", '257 3 14 "fYA="')

    return {
        "trust_anchors": [ta],
        "zones": [truncated_selfsigned],
        "truncated_selfsigned": True,
    }


def test_truncated_dnskey(ns9):
    msg = isctest.query.create("a.truncated.selfsigned.", "A")
    with ns9.watch_log_from_here() as watcher:
        res = isctest.query.tcp(msg, ns9.ip)
        watcher.wait_for_all(
            [
                Re("truncated.selfsigned/DNSKEY.*insecurity proof failed: success"),
                Re("truncated.selfsigned/DNSKEY.*validation failed"),
            ]
        )
    isctest.check.servfail(res)
