"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from typing import Optional

import isctest
from isctest.util import param


SINGLE_ALIVE = [
    # single server alive, others dead

    param("ns3-reply_default-drop.two-ns", "ns3"),
    param("ns4-reply_default-drop.two-ns", "ns4"),

    param("ns3-reply_default-drop.three-ns", "ns3"),
    param("ns4-reply_default-drop.three-ns", "ns4"),
    param("ns5-reply_default-drop.three-ns", "ns5"),

    param("ns3-reply_default-drop.four-ns", "ns3"),
    param("ns4-reply_default-drop.four-ns", "ns4"),
    param("ns5-reply_default-drop.four-ns", "ns5"),
    param("ns6-reply_default-drop.four-ns", "ns6"),

    param("ns3-reply_default-drop.six-ns", "ns3"),
    param("ns4-reply_default-drop.six-ns", "ns4"),
    param("ns5-reply_default-drop.six-ns", "ns5"),
    param("ns6-reply_default-drop.six-ns", "ns6"),
    param("ns7-reply_default-drop.six-ns", "ns7"),
    param("ns8-reply_default-drop.six-ns", "ns8"),

    # single server alive and delayed responses, others dead

    param("ns3-delay-100_default-drop.two-ns", "ns3"),
    param("ns4-delay-100_default-drop.two-ns", "ns4"),

    param("ns3-delay-100_default-drop.three-ns", "ns3"),
    param("ns4-delay-100_default-drop.three-ns", "ns4"),
    param("ns5-delay-100_default-drop.three-ns", "ns5"),

    param("ns3-delay-100_default-drop.four-ns", "ns3"),
    param("ns4-delay-100_default-drop.four-ns", "ns4"),
    param("ns5-delay-100_default-drop.four-ns", "ns5"),
    param("ns6-delay-100_default-drop.four-ns", "ns6"),

    param("ns3-delay-100_default-drop.six-ns", "ns3"),
    param("ns4-delay-100_default-drop.six-ns", "ns4"),
    param("ns5-delay-100_default-drop.six-ns", "ns5"),
    param("ns6-delay-100_default-drop.six-ns", "ns6"),
    param("ns7-delay-100_default-drop.six-ns", "ns7"),
    param("ns8-delay-100_default-drop.six-ns", "ns8"),
]

# TODO: use hypothesis to generate test cases

ALL_DELAYED = [
    "default-delay-100.two-ns",
    "default-delay-100.three-ns",
    "default-delay-100.four-ns",
    "default-delay-100.six-ns",

    "default-delay-200.two-ns",
    "default-delay-200.three-ns",
    "default-delay-200.four-ns",
    "default-delay-200.six-ns",

    "default-delay-500.two-ns",
    "default-delay-500.three-ns",
    "default-delay-500.four-ns",
    "default-delay-500.six-ns",

    "ns3-delay-100_default-delay-500.two-ns",
    "ns4-delay-100_default-delay-500.two-ns",

    "ns3-delay-100_default-delay-500.three-ns",
    "ns4-delay-100_default-delay-500.three-ns",
    "ns5-delay-100_default-delay-500.three-ns",

    "ns3-delay-100_default-delay-500.four-ns",
    "ns4-delay-100_default-delay-500.four-ns",
    "ns5-delay-100_default-delay-500.four-ns",
    "ns6-delay-100_default-delay-500.four-ns",

    "ns3-delay-100_default-delay-500.six-ns",
    "ns4-delay-100_default-delay-500.six-ns",
    "ns5-delay-100_default-delay-500.six-ns",
    "ns6-delay-100_default-delay-500.six-ns",
    "ns7-delay-100_default-delay-500.six-ns",
    "ns8-delay-100_default-delay-500.six-ns",
]

ONE_OR_MORE_DEAD = [
    "ns3-delay-100_ns4-reply_default-drop.three-ns",
    "ns4-delay-100_ns5-reply_default-drop.three-ns",

    "ns6-delay-100_ns7-delay-200_default-drop.four-ns",
    "ns4-delay-200_ns5-delay-100_default-drop.four-ns",

    "ns3-delay-100_ns4-delay-200_ns5-delay-300_default-drop.six-ns",
    "ns4-delay-200_ns6-delay-300_ns8-delay-100_default-drop.six-ns",
    "ns6-delay-300_ns7-delay-200_ns8-delay-100_default-drop.six-ns",
]

MIXED = ALL_DELAYED + ONE_OR_MORE_DEAD


def check_resolution(qname: str, ns_origin: Optional[str] = None):
    isctest.log.info(f"sending query for {qname} TXT")
    msg = isctest.query.create(qname, "TXT")
    res = isctest.query.tcp(msg, "10.53.0.9", timeout=20, attempts=1)  # TODO attempts=1 may be unstable in CI

    isctest.log.info("check we got a NOERROR reply")
    isctest.check.noerror(res)

    if ns_origin is not None:
        isctest.log.info(f"check the reply originated from {ns_origin}")
        text = res.answer[0][0].strings[0].decode("ascii")
        ns = text.split()[0]
        assert (
            ns_origin == ns
        ), f"expected answer to come from {ns_origin}, but it came from {ns}"
