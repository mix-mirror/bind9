"""
Copyright (C) Internet Systems Consortium, Inc. ("ISC")

SPDX-License-Identifier: MPL-2.0

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0.  If a copy of the MPL was not distributed with this
file, you can obtain one at https://mozilla.org/MPL/2.0/.

See the COPYRIGHT file distributed with this work for additional
information regarding copyright ownership.
"""

from dataclasses import dataclass
from pathlib import Path

import json

from cryptography.hazmat.primitives import serialization

import dns.dnssec
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from isctest.asyncserver import (
    AsyncDnsServer,
    DomainHandler,
    QnameQtypeHandler,
    StaticResponseHandler,
)

TTL = 300
PARENT = "f044.test."
CHILD = f"child.{PARENT}"
QUERY = f"q.{PARENT}"
SERVICE = f"svc.{CHILD}"
FORGED_A = "6.6.6.6"
LEGIT_A = "192.0.2.111"


@dataclass(frozen=True)
class Key:
    zone: str
    private_key: object
    dnskey: dns.rdata.Rdata
    ds: dns.rdata.Rdata


def load_keys() -> dict[str, Key]:
    path = Path("keys.json")
    with path.open(encoding="utf-8") as keys_file:
        raw_keys = json.load(keys_file)

    keys = {}
    for zone, raw_key in raw_keys.items():
        private_key = serialization.load_pem_private_key(
            raw_key["private_pem"].encode("ascii"),
            password=None,
        )
        keys[zone] = Key(
            zone,
            private_key,
            dns.rdata.from_text(
                dns.rdataclass.IN, dns.rdatatype.DNSKEY, raw_key["dnskey"]
            ),
            dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, raw_key["ds"]),
        )
    return keys


KEYS = load_keys()


def rrset(owner: str, rdtype: dns.rdatatype.RdataType, *rdatas: str) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, TTL, dns.rdataclass.IN, rdtype, *rdatas)


def rrset_from_rdata(owner: str, rdata: dns.rdata.Rdata) -> dns.rrset.RRset:
    return dns.rrset.from_rdata(owner, TTL, rdata)


def soa(zone: str) -> dns.rrset.RRset:
    return rrset(
        zone,
        dns.rdatatype.SOA,
        f"ns.{zone} hostmaster.{zone} 1 3600 600 86400 300",
    )


def dnskey(zone: str) -> dns.rrset.RRset:
    return rrset_from_rdata(zone, KEYS[zone].dnskey)


def ds(zone: str) -> dns.rrset.RRset:
    return rrset_from_rdata(zone, KEYS[zone].ds)


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


class ParentDnskeyHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [PARENT]
    qtypes = [dns.rdatatype.DNSKEY]
    answer = signed(dnskey(PARENT), KEYS[PARENT])


class ParentSoaHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [PARENT]
    qtypes = [dns.rdatatype.SOA]
    answer = signed(soa(PARENT), KEYS[PARENT])


class ChildDsHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [CHILD]
    qtypes = [dns.rdatatype.DS]
    answer = signed(ds(CHILD), KEYS[PARENT])


class ChildDnskeyHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [CHILD]
    qtypes = [dns.rdatatype.DNSKEY]
    answer = signed(dnskey(CHILD), KEYS[CHILD])


class ChildSoaHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [CHILD]
    qtypes = [dns.rdatatype.SOA]
    answer = signed(soa(CHILD), KEYS[CHILD])


class AncestorSignedAdditionalHandler(QnameQtypeHandler, StaticResponseHandler):
    """
    The attack: answer q.f044.test./MX with an additional A for the in-bailiwick
    target svc.child.f044.test. that is forged and signed by the parent (child's
    ancestor) rather than the child that owns the name.
    """

    qnames = [QUERY]
    qtypes = [dns.rdatatype.MX]
    answer = signed(rrset(QUERY, dns.rdatatype.MX, f"10 {SERVICE}"), KEYS[PARENT])
    additional = signed(rrset(SERVICE, dns.rdatatype.A, FORGED_A), KEYS[PARENT])


class ServiceAHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [SERVICE]
    qtypes = [dns.rdatatype.A]
    answer = signed(rrset(SERVICE, dns.rdatatype.A, LEGIT_A), KEYS[CHILD])


class ChildNodataHandler(DomainHandler, StaticResponseHandler):
    domains = [CHILD]
    authority = signed(soa(CHILD), KEYS[CHILD])


class ParentNodataHandler(DomainHandler, StaticResponseHandler):
    domains = [PARENT]
    authority = signed(soa(PARENT), KEYS[PARENT])


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        ParentDnskeyHandler(),
        ParentSoaHandler(),
        ChildDsHandler(),
        ChildDnskeyHandler(),
        ChildSoaHandler(),
        AncestorSignedAdditionalHandler(),
        ServiceAHandler(),
        ChildNodataHandler(),
        ParentNodataHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
