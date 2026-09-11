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

pytestmark = pytest.mark.requires_zones_loaded("ns4")


def test_negated_nested_acl_glue(ns4):
    """
    The "glue" zone's allow-query is { 10.53.0.1; 10.53.0.2;
    !{ 10.53.0.0/30; }; }.  The two host entries create a radix glue
    node at 10.53.0.0/30, which the negated prefix then lands on; it
    must still be merged as a deny entry.
    """
    msg = isctest.query.create("glue.", "SOA")

    # the two explicitly allowed hosts can query
    response = isctest.query.udp(msg, ns4.ip, source="10.53.0.1")
    isctest.check.noerror(response)
    response = isctest.query.udp(msg, ns4.ip, source="10.53.0.2")
    isctest.check.noerror(response)

    # 10.53.0.3 matches only the negated 10.53.0.0/30 and must be denied
    response = isctest.query.udp(msg, ns4.ip, source="10.53.0.3")
    isctest.check.refused(response)
