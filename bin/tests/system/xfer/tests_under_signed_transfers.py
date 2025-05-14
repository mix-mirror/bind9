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

# pylint: disable=unused-import
from xfer.common import check_rdata_in_txt_record, sendcmd, set_ns4_as_secondary_for_nil


@pytest.mark.parametrize(
    "command_file,expected_rdata,named_log_line",
    [
        (  # unsigned transfer
            "unsigned",
            "unsigned AXFR",
            "Transfer status: expected a TSIG or SIG(0)",
        ),
        (  # bad keydata
            "badkeydata",
            "bad keydata",
            "Transfer status: tsig verify failure",
        ),
        (  # partially-signed transfer
            "partial",
            "partially signed AXFR",
            "Transfer status: expected a TSIG or SIG(0)",
        ),
        (  # unknown key
            "unknownkey",
            "unknown key AXFR",
            "tsig key 'tsig_key': key name and algorithm do not match",
        ),
        (  # incorrect key
            "wrongkey",
            "incorrect key AXFR",
            "tsig key 'tsig_key': key name and algorithm do not match",
        ),
        (  # bad question section
            "wrongname",
            "wrong question AXFR",
            "question name mismatch",
        ),
        (  # bad message id
            "badmessageid",
            "bad message id",
            "Transfer status: unexpected error",
        ),
        (  # mismatched SOA
            "soamismatch",
            "SOA mismatch AXFR",
            "Transfer status: FORMERR",
        ),
    ],
)
def test_under_signed_transfer(
    command_file, expected_rdata, named_log_line, set_ns4_as_secondary_for_nil, ns4
):  # pylint: disable=unused-argument,redefined-outer-name
    def check_rdata_not_in_txt_record(rdata):
        check_rdata_in_txt_record(rdata, should_exist=False)

    sendcmd(command_file)
    with ns4.watch_log_from_here() as watcher:
        ns4.rndc("retransfer nil.")
        watcher.wait_for_line(named_log_line)

    check_rdata_not_in_txt_record(expected_rdata)
