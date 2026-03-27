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

from re import Pattern

import re


def transfer_message(
    zone: str, source_ns: str | None, msg: str, port: int | None = None
) -> str | Pattern:
    """Return the expected log message for an incoming zone transfer.

    Mirrors the format produced by xfrin_log() in lib/dns/xfrin.c:

        transfer of '<zone>/IN' from <source_ns>#<port>: <msg>

    When source_ns or port is None a compiled regex is returned with the
    unknown part replaced by a wildcard (.*), which is useful when the
    primary address or port is not known in advance.  Passing both
    source_ns and port as concrete values returns a plain string.

    Args:
        zone:      Zone name (without class, e.g. "example.com").
        source_ns: Source nameserver IP address string (e.g. "10.53.0.1"),
                   or None to match any source address.
        msg:       Transfer status or other message (e.g. "Transfer status: success").
        port:      Source port number, or None to match any port.
    """
    source_str = source_ns or ".*"
    port_str = str(port) if port is not None else "[0-9]+"

    if source_ns is not None and port is not None:
        return f"transfer of '{zone}/IN' from {source_str}#{port_str}: {msg}"

    return re.compile(
        re.escape(f"transfer of '{zone}/IN' from ")
        + f"{source_str}#{port_str}"
        + re.escape(f": {msg}")
    )
