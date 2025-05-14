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


import isctest


# checking whether dig calculates AXFR statistics correctly
def test_dig_and_named_axfr_stats(named_port, ns3):
    # Loop until the secondary server manages to transfer the "xfer-stats" zone so
    # that we can both check dig output and immediately proceed with the next test.
    # Use -b so that we can discern between incoming and outgoing transfers in ns3
    # logs later on.
    output = isctest.run.cmd(
        [
            isctest.vars.ALL["DIG"],
            "+tcp",
            "+noadd",
            "+nosea",
            "+nostat",
            "+noquest",
            "+nocomm",
            "+nocmd",
            "-p",
            str(named_port),
            "+edns",
            "+nocookie",
            "+noexpire",
            "+stat",
            "-b",
            "10.53.0.2",
            "@10.53.0.3",
            "xfer-stats.",
            "AXFR",
        ],
        log_stdout=True,
    ).stdout.decode("utf-8")
    assert "; Transfer failed" not in output
    assert ";; XFR size: 10003 records (messages 16, bytes 218403)" in output

    # Note: in the next two tests, we use ns3 logs for checking both incoming and
    # outgoing transfer statistics as ns3 is both a secondary server (for ns1) and a
    # primary server (for dig queries from the previous test) for "xfer-stats".
    with ns3.watch_log_from_start() as watcher_transfer_completed:
        pattern_transfer_completed = f"transfer of 'xfer-stats/IN' from 10.53.0.1#{named_port}: Transfer completed: 16 messages, 10003 records, 218403 bytes"
        watcher_transfer_completed.wait_for_line(pattern_transfer_completed)

    # checking whether named calculates outgoing AXFR statistics correctly
    with ns3.watch_log_from_start() as watcher_axfr_ended:
        pattern_axfr_ended = "transfer of 'xfer-stats/IN': AXFR ended: 16 messages, 10003 records, 218403 bytes"
        watcher_axfr_ended.wait_for_line(pattern_axfr_ended)
