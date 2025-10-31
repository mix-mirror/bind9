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

import isctest


def nsupdate(config):
    isctest.run.cmd(isctest.vars.ALL["NSUPDATE"], input_text=config.encode("utf-8"))


# test that a zone with too many records is rejected (IXFR)
def test_ixfr_too_many_records(named_port, ns6):
    with ns6.watch_log_from_here(timeout=20) as watcher:
        nsupdate_config = f"""
        zone ixfr-too-big
        server 10.53.0.1 {named_port}
        update add the-31st-record.ixfr-too-big 0 TXT this is it
        send
        """
        nsupdate(nsupdate_config)
        pattern = re.compile(
            f"'ixfr-too-big/IN' from 10.53.0.1#{named_port}: Transfer status: too many records"
        )
        watcher.wait_for_line(pattern)


# test that a zone with too many diffs (IXFR) is retried with AXFR
def test_ixfr_too_many_diffs(named_port, ns6):
    with ns6.watch_log_from_here() as watcher_retry_axfr:
        with ns6.watch_log_from_here() as watcher_transfer_status:
            nsupdate_config = f"""
            zone ixfr-too-many-diffs
            server 10.53.0.1 {named_port}
            update add the-31st-record.ixfr-too-many-diffs 0 TXT too
            update add the-32nd-record.ixfr-too-many-diffs 0 TXT many
            update add the-33rd-record.ixfr-too-many-diffs 0 TXT diffs
            update add the-34th-record.ixfr-too-many-diffs 0 TXT for
            update add the-35th-record.ixfr-too-many-diffs 0 TXT ixfr
            send
            """
            nsupdate(nsupdate_config)
            pattern_transfer_status_success = re.compile(
                f"'ixfr-too-many-diffs/IN' from 10.53.0.1#{named_port}: Transfer status: success"
            )
            watcher_transfer_status.wait_for_line(pattern_transfer_status_success)
        pattern_transfer_retry_axfr = re.compile(
            f"'ixfr-too-many-diffs/IN' from 10.53.0.1#{named_port}: too many diffs, retrying with AXFR"
        )
        watcher_retry_axfr.wait_for_line(pattern_transfer_retry_axfr)


# test that a zone with too many records is rejected (AXFR)
def test_axfr_too_many_records(ns6):
    with ns6.watch_log_from_start() as watcher:
        watcher.wait_for_line(re.compile("'axfr-too-big/IN'.*: too many records"))
