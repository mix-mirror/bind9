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

import re
import time


# check that we asked for and received a EDNS EXPIRE response when transfering from a secondary
def test_edns_expire_from_secondary(ns7):
    pattern = re.compile(
        "zone edns-expire/IN: zone transfer finished: success, expire=1814[0-4][0-9][0-9]"
    )
    with ns7.watch_log_from_start() as watcher:
        watcher.wait_for_line(pattern)


# check that we ask for and get a EDNS EXPIRE response when refreshing
def test_edns_expire_refresh(ns7):
    # make sure the EDNS EXPIRE of 1814400 decreases a slightly
    time.sleep(1)
    with ns7.watch_log_from_here() as watcher:
        ns7.rndc("refresh edns-expire.")
        pattern = re.compile(
            "zone edns-expire/IN: got EDNS EXPIRE of 1814[0-3][0-9][0-9]"
        )
        watcher.wait_for_line(pattern)
