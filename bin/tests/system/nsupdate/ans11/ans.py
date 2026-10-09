# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, you can obtain one at https://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import AsyncDnsServer
from isctest.asyncserver.handlers import AxfrHandler, StaticResponseHandler
from isctest.asyncserver.matchers import Qname, Qtype

ZONE = "sigaxfr.nil."
NS_NAME = "ns.sigaxfr.nil."
HOST = "host.sigaxfr.nil."


def rrset(name: str, rdtype: dns.rdatatype.RdataType, *rdata: str) -> dns.rrset.RRset:
    return dns.rrset.from_text(name, 3600, dns.rdataclass.IN, rdtype, *rdata)


def soa() -> dns.rrset.RRset:
    return rrset(
        ZONE,
        dns.rdatatype.SOA,
        "ns.sigaxfr.nil. hostmaster.sigaxfr.nil. 1 3600 1200 604800 3600",
    )


def sig(covers: dns.rdatatype.RdataType) -> dns.rrset.RRset:
    covered = dns.rdatatype.to_text(covers)
    return dns.rrset.from_text(
        HOST,
        600,
        dns.rdataclass.IN,
        dns.rdatatype.SIG,
        f"{covered} 6 2 600 20260331170000 20260318160000 21831 . 0000",
    )


class SoaHandler(StaticResponseHandler):
    matcher = Qname(ZONE) & Qtype(dns.rdatatype.SOA)
    answer = [soa()]


class SigAxfrHandler(AxfrHandler):
    """
    Serve an AXFR carrying two legacy SIG (24) rdatas at one owner whose
    body "covered type" fields differ (A, MX); per RFC 3755 SIG has no
    covered-type semantics, so the transferring secondary must store both
    in a single opaque rdataset.
    """

    matcher = Qname(ZONE) & Qtype(dns.rdatatype.AXFR)
    initial_soa = soa()
    zone_contents = [
        rrset(ZONE, dns.rdatatype.NS, NS_NAME),
        rrset(NS_NAME, dns.rdatatype.A, "10.53.0.11"),
        # dnspython groups SIG rdatas by their covered type, so each one
        # needs its own RRset; on the wire they are separate RRs anyway.
        sig(dns.rdatatype.A),
        sig(dns.rdatatype.MX),
    ]
    final_soa = soa()


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(SoaHandler(), SigAxfrHandler())
    server.run()


if __name__ == "__main__":
    main()
