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

from serverselect.common import check_resolution, SINGLE_ALIVE, MIXED

def bootstrap():
    return {
        "nsset_delay": 0,
    }

@pytest.fixture(autouse=True)
def flush(ns9):
    isctest.log.info("flush ns9 cache")
    ns9.rndc("flush", log=False)


@pytest.mark.parametrize("qname, ns_origin", SINGLE_ALIVE)
def test_single_alive(qname, ns_origin):
    check_resolution(qname, ns_origin)


@pytest.mark.parametrize("qname", MIXED)
def test_mixed(qname):
    check_resolution(qname, None)
