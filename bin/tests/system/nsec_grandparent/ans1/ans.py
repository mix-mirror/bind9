"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from collections.abc import AsyncGenerator
from dataclasses import dataclass
from pathlib import Path

import json

from cryptography.hazmat.primitives import serialization

import dns.dnssec
import dns.name
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    DnsResponseSend,
    DomainHandler,
    QnameQtypeHandler,
    QueryContext,
    StaticResponseHandler,
)

TTL = 300
PARENT = "p031.test."
CHILD = f"c.{PARENT}"
GRANDCHILD = f"grand.{CHILD}"
GRANDCHILD3 = f"grand3.{CHILD}"
FORGED_A = "6.6.6.60"
CHILD_DS = "12345 13 2 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"


@dataclass(frozen=True)
class Key:
    zone: str
    private_key: object
    dnskey: dns.rdata.Rdata


def load_key() -> Key:
    path = Path("keys.json")
    with path.open(encoding="utf-8") as keys_file:
        raw_key = json.load(keys_file)[PARENT]

    private_key = serialization.load_pem_private_key(
        raw_key["private_pem"].encode("ascii"),
        password=None,
    )
    return Key(
        PARENT,
        private_key,
        dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY, raw_key["dnskey"]),
    )


def rrset(
    owner: dns.name.Name | str, rdtype: dns.rdatatype.RdataType, *rdatas: str
) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, TTL, dns.rdataclass.IN, rdtype, *rdatas)


def rrset_from_rdata(owner: str, rdata: dns.rdata.Rdata) -> dns.rrset.RRset:
    return dns.rrset.from_rdata(owner, TTL, rdata)


def signed(covered: dns.rrset.RRset, signer: Key) -> list[dns.rrset.RRset]:
    rrsig = dns.dnssec.sign(
        covered,
        signer.private_key,
        signer.zone,
        signer.dnskey,
        lifetime=86400,
        verify=True,
    )
    return [covered, dns.rrset.from_rdata(covered.name, covered.ttl, rrsig)]


def soa() -> dns.rrset.RRset:
    return rrset(
        PARENT,
        dns.rdatatype.SOA,
        f"ns.{PARENT} hostmaster.{PARENT} 1 3600 600 86400 300",
    )


def dnskey(parent_key: Key) -> dns.rrset.RRset:
    return rrset_from_rdata(PARENT, parent_key.dnskey)


def child_ds() -> dns.rrset.RRset:
    return rrset(CHILD, dns.rdatatype.DS, CHILD_DS)


def nsec(owner: str, next_name: str, *types: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NSEC, f"{next_name} {' '.join(types)}")


def grandchild_nsec_lie() -> dns.rrset.RRset:
    return nsec(GRANDCHILD, f"grandz.{CHILD}", "NS", "RRSIG", "NSEC")


def grandchild3_nsec3_lie() -> dns.rrset.RRset:
    digest = dns.dnssec.nsec3_hash(
        GRANDCHILD3, salt=None, iterations=0, algorithm="SHA1"
    ).lower()
    owner = f"{digest}.{PARENT}"
    return rrset(owner, dns.rdatatype.NSEC3, f"1 0 0 - {digest} NS")


def forged_a(owner: dns.name.Name) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.A, FORGED_A)


def forged_nodata(nsec_rr: dns.rrset.RRset, signer: Key) -> list[dns.rrset.RRset]:
    return signed(soa(), signer) + signed(nsec_rr, signer)


KEY = load_key()


class ParentDnskeyHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [PARENT]
    qtypes = [dns.rdatatype.DNSKEY]
    answer = signed(dnskey(KEY), KEY)


class ParentSoaHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [PARENT]
    qtypes = [dns.rdatatype.SOA]
    answer = signed(soa(), KEY)


class ChildDsHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [CHILD]
    qtypes = [dns.rdatatype.DS]
    answer = signed(child_ds(), KEY)


class GrandchildDsNsecHandler(QnameQtypeHandler, StaticResponseHandler):
    """Forge a grandparent-signed NODATA proof for the grandchild DS (NSEC)."""

    qnames = [GRANDCHILD]
    qtypes = [dns.rdatatype.DS]
    authority = forged_nodata(grandchild_nsec_lie(), KEY)


class Grandchild3DsNsec3Handler(QnameQtypeHandler, StaticResponseHandler):
    """
    Same forgery as GrandchildDsNsecHandler, expressed as NSEC3 so that the
    resolver reaches is_insecure_referral()'s trynsec3 arm: an NSEC3 owned by
    the grandparent zone that matches the grandchild's hash and shows an
    (insecure) delegation, with the NS bit set and the DS bit clear.
    """

    qnames = [GRANDCHILD3]
    qtypes = [dns.rdatatype.DS]
    authority = forged_nodata(grandchild3_nsec3_lie(), KEY)


class ForgedAHandler(DomainHandler):
    """Serve the attacker's forged A for any name below the grandchildren."""

    domains = [GRANDCHILD, GRANDCHILD3]

    def match(self, qctx: QueryContext) -> bool:
        return qctx.qtype == dns.rdatatype.A and super().match(qctx)

    async def get_responses(
        self, qctx: QueryContext
    ) -> AsyncGenerator[DnsResponseSend, None]:
        qctx.response.answer.append(forged_a(qctx.qname))
        yield DnsResponseSend(qctx.response)


class NxdomainFallbackHandler(DomainHandler, StaticResponseHandler):
    domains = [PARENT]
    rcode = dns.rcode.NXDOMAIN


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        ParentDnskeyHandler(),
        ParentSoaHandler(),
        ChildDsHandler(),
        GrandchildDsNsecHandler(),
        Grandchild3DsNsec3Handler(),
        ForgedAHandler(),
        NxdomainFallbackHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
