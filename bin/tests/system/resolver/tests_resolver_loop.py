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


import isctest


def test_resolver_loop_detected(servers):
    resolver = servers["ns5"]

    resolver.rndc("flush")
    msg = isctest.query.create("blah.fetchloop.tld.", "TXT")
    res = isctest.query.udp(msg, "10.53.0.5")
    # Dummy tests
    isctest.check.noerror(res)
    assert res.answer[0].ttl == 300

    # Test that "fetch loop detected" is logged.
    resolver.log.expect("fetch loop detected...")
    # No hung fetch on shut down.
    resolver.log.prohibit("shut down hung fetch while resolving")
