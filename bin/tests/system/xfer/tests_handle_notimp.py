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


# pylint: disable=unused-import
from xfer.common import check_rdata_in_txt_record, sendcmd, set_ns4_as_secondary_for_nil


def test_handle_ixfr_notimp(
    set_ns4_as_secondary_for_nil, named_port, ns4
):  # pylint: disable=unused-argument,redefined-outer-name
    sendcmd("goodaxfr")
    with ns4.watch_log_from_here() as watcher_retransfer_nil_success:
        ns4.rndc("retransfer nil.")
        retransfer_nil_pattern = re.compile(
            f"transfer of 'nil/IN' from 10.53.0.5#{named_port}: Transfer status: success"
        )
        watcher_retransfer_nil_success.wait_for_line(retransfer_nil_pattern)

    sendcmd("ixfrnotimp")
    with ns4.watch_log_from_here() as watcher_transfer_success:
        with ns4.watch_log_from_here() as watcher_requesting_ixfr:
            ns4.rndc("refresh nil.")
            watcher_requesting_ixfr.wait_for_line(
                "zone nil/IN: requesting IXFR from 10.53.0.5"
            )
        pattern = re.compile(
            f"transfer of 'nil/IN' from 10.53.0.5#{named_port}: Transfer status: success"
        )
        watcher_transfer_success.wait_for_line(pattern)

    check_rdata_in_txt_record("IXFR NOTIMP")


def test_handle_edns_notimp(
    set_ns4_as_secondary_for_nil, ns4
):  # pylint: disable=unused-argument,redefined-outer-name
    ns4.rndc("null testing EDNS NOTIMP")
    sendcmd("ednsnotimp")
    with ns4.watch_log_from_here() as watcher:
        ns4.rndc("retransfer nil.")
        watcher.wait_for_line("Transfer status: NOTIMP")


def test_handle_edns_formerr(
    set_ns4_as_secondary_for_nil, named_port, ns4
):  # pylint: disable=unused-argument,redefined-outer-name
    ns4.rndc("null testing EDNS FORMERR")
    sendcmd("ednsformerr")
    with ns4.watch_log_from_here() as watcher:
        ns4.rndc("retransfer nil.")
        pattern = re.compile(
            f"transfer of 'nil/IN' from 10.53.0.5#{named_port}: Transfer status: success"
        )
        watcher.wait_for_line(pattern)
    check_rdata_in_txt_record("EDNS FORMERR")
