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

import dns.message

from xfer.common import validate_axfr_from_query_and_file


def test_zone_transfer_fallback_to_dns_after_dot_failed():
    msg = dns.message.make_query("dot-fallback.", "AXFR")
    validate_axfr_from_query_and_file(msg, "10.53.0.2", "response3.good")


# First, test that named tries the next primary in the list when the first one
# fails (XoT -> Do53). Then, test that named tries the next primary in the list
# when the first one is already marked as unreachable (XoT -> Do53).
def test_xot_primary_try_next(named_port, ns6):
    def retransfer_and_check_log():
        pattern = f"'xot-primary-try-next/IN' from 10.53.0.1#{named_port}: Transfer status: success"
        with ns6.watch_log_from_here(timeout=60) as watcher:
            ns6.rndc("retransfer xot-primary-try-next.")
            watcher.wait_for_line(pattern)

    retransfer_and_check_log()
    retransfer_and_check_log()
