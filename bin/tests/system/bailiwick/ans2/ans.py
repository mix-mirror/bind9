"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from typing import AsyncGenerator

import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    DnsResponseSend,
    QueryContext,
    ResponseAction,
)

from bailiwick_ans import ResponseSpoofer, spoofing_server


ATTACKER_IP = "10.53.0.3"
TTL = 3600


def main() -> None:
    spoofing_server().run()


if __name__ == "__main__":
    main()
