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


def test_retransfer_with_force(named_port, templates, ns1, ns6):
    ns_params = "-D xfer-ns1 -m record -c named.conf -d 99 -g -T maxcachesize=2097152 -T transferinsecs"

    # Restart ns1 with -T transferslowly
    ns1.stop()
    templates.render("ns1/named.conf", {"enable_some_zones": False})
    ns1.start(
        [
            "--noclean",
            "--restart",
            "--port",
            str(named_port),
            "--",
            f"{ns_params} -T transferslowly",
        ]
    )

    # Wait for at least one message
    with ns6.watch_log_from_here() as watcher:
        ns6.rndc("retransfer axfr-rndc-retransfer-force.")
        watcher.wait_for_line(
            f"'axfr-rndc-retransfer-force/IN' from 10.53.0.1#{named_port}: received"
        )

    # Issue a retransfer-force command which should cancel the ongoing
    # transfer and start a new one.
    with ns6.watch_log_from_here(timeout=30) as watcher_transfer_success:
        with ns6.watch_log_from_here() as watcher_transfer_shutting_down:
            ns6.rndc("retransfer -force axfr-rndc-retransfer-force.")
            watcher_transfer_shutting_down.wait_for_line(
                f"'axfr-rndc-retransfer-force/IN' from 10.53.0.1#{named_port}: Transfer status: shutting down"
            )
        # Wait for the new transfer to complete successfully
        watcher_transfer_success.wait_for_line(
            f"'axfr-rndc-retransfer-force/IN' from 10.53.0.1#{named_port}: Transfer status: success"
        )

    # Test min-transfer-rate-in with 5 seconds timeout
    with ns6.watch_log_from_here() as watcher:
        ns6.rndc("retransfer axfr-min-transfer-rate.")
        watcher.wait_for_line("minimum transfer rate reached: timed out")

    # Test max-transfer-time-in with 1 second timeout
    with ns6.watch_log_from_here() as watcher:
        ns6.rndc("retransfer axfr-max-transfer-time.")
        watcher.wait_for_line("maximum transfer time exceeded: timed out")

    ns1.stop()
    templates.render(
        "ns1/named.conf",
        {"enable_some_zones": False, "enable_only_axfr_max_idle_time": True},
    )
    ns1.start(
        [
            "--noclean",
            "--restart",
            "--port",
            str(named_port),
            "--",
            f"{ns_params} -T transferstuck",
        ]
    )

    # Test max-transfer-idle-in with 50 seconds timeout
    start_time = time.time()
    with ns6.watch_log_from_here(timeout=60) as watcher:
        ns6.rndc("retransfer axfr-max-idle-time.")
        watcher.wait_for_line("maximum idle time exceeded: timed out")
    end_time = time.time()
    assert (
        50 <= (end_time - start_time) < 59
    ), "max-transfer-idle-in did not wait for the expected time"

    ns1.stop()
    templates.render("ns1/named.conf")
    ns1.start(
        [
            "--noclean",
            "--restart",
            "--port",
            str(named_port),
        ]
    )
