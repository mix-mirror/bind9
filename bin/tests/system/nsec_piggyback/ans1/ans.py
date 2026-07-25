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
from datetime import datetime, timedelta, timezone
from pathlib import Path

import base64
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
    QnameHandler,
    QnameQtypeHandler,
    StaticResponseHandler,
)

TTL = 300
PARENT = "p22.hack."
CHILD = f"c.{PARENT}"
CHILD_NS = f"ns.{CHILD}"
VICTIM = f"victim.{PARENT}"
AAC = f"aac.{PARENT}"
CHILD_NEXT = f"ns1.{PARENT}"
PRIME_NX = f"0.{PARENT}"

CHILD_NS_A = "10.53.0.2"
VICTIM_A = "192.0.2.99"
AAC_A = "192.0.2.77"


@dataclass(frozen=True)
class Key:
    zone: str
    private_key: object
    dnskey: dns.rdata.Rdata


def rrset(owner: str, rdtype: dns.rdatatype.RdataType, *rdatas: str) -> dns.rrset.RRset:
    return dns.rrset.from_text(owner, TTL, dns.rdataclass.IN, rdtype, *rdatas)


def load_keys() -> dict[str, Key]:
    with Path("keys.json").open(encoding="utf-8") as keys_file:
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
        )

    return keys


PARENT_KEY = load_keys()[PARENT]


def rrsig(covered: dns.rrset.RRset, signer: Key) -> dns.rrset.RRset:
    rdata = dns.dnssec.sign(
        covered,
        signer.private_key,
        signer.zone,
        signer.dnskey,
        lifetime=86400,
        verify=True,
    )
    return dns.rrset.from_rdata(covered.name, covered.ttl, rdata)


def signed(covered: dns.rrset.RRset, signer: Key) -> list[dns.rrset.RRset]:
    return [covered, rrsig(covered, signer)]


def garbage_rrsig(covered: dns.rrset.RRset, signer: Key) -> dns.rrset.RRset:
    now = datetime.now(timezone.utc)
    inception = (now - timedelta(hours=1)).strftime("%Y%m%d%H%M%S")
    expiration = (now + timedelta(days=1)).strftime("%Y%m%d%H%M%S")
    labels = len(covered.name.labels) - 1
    key_tag = dns.dnssec.key_id(signer.dnskey)
    signature = base64.b64encode(bytes(64)).decode("ascii")
    text = (
        f"{dns.rdatatype.to_text(covered.rdtype)} "
        f"{signer.dnskey.algorithm} {labels} {covered.ttl} "
        f"{expiration} {inception} {key_tag} {signer.zone} {signature}"
    )
    rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.RRSIG, text)
    return dns.rrset.from_rdata(covered.name, covered.ttl, rdata)


def garbage_signed(covered: dns.rrset.RRset, signer: Key) -> list[dns.rrset.RRset]:
    return [covered, garbage_rrsig(covered, signer)]


def dnskey() -> dns.rrset.RRset:
    return dns.rrset.from_rdata(PARENT, TTL, PARENT_KEY.dnskey)


def soa(zone: str) -> dns.rrset.RRset:
    return rrset(
        zone,
        dns.rdatatype.SOA,
        f"ns.{zone} hostmaster.{zone} 1 3600 600 86400 300",
    )


def nsec(owner: str, next_name: str, *types: str) -> dns.rrset.RRset:
    return rrset(owner, dns.rdatatype.NSEC, f"{next_name} {' '.join(types)}")


def nsec_apex() -> dns.rrset.RRset:
    return nsec(PARENT, AAC, "NS", "SOA", "RRSIG", "NSEC", "DNSKEY")


def nsec_deleg_child() -> dns.rrset.RRset:
    return nsec(CHILD, CHILD_NEXT, "NS", "RRSIG", "NSEC")


def stuffed_ent_nsec() -> dns.rrset.RRset:
    return nsec(f"t.{PARENT}", f"sub.{VICTIM}", "A", "RRSIG", "NSEC")


def stuffed_range_nsec() -> dns.rrset.RRset:
    return nsec(f"aab.{PARENT}", f"az.{PARENT}", "A", "RRSIG", "NSEC")


class ParentDnskeyHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [PARENT]
    qtypes = [dns.rdatatype.DNSKEY]
    answer = signed(dnskey(), PARENT_KEY)


class ParentSoaHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [PARENT]
    qtypes = [dns.rdatatype.SOA]
    answer = signed(soa(PARENT), PARENT_KEY)


class PrimeNxdomainHandler(QnameHandler, StaticResponseHandler):
    qnames = [PRIME_NX]
    rcode = dns.rcode.NXDOMAIN
    authority = signed(soa(PARENT), PARENT_KEY) + signed(nsec_apex(), PARENT_KEY)


class ChildDsHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [CHILD]
    qtypes = [dns.rdatatype.DS]
    authority = signed(soa(PARENT), PARENT_KEY) + signed(nsec_deleg_child(), PARENT_KEY)


class VictimAHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [VICTIM]
    qtypes = [dns.rdatatype.A]
    answer = signed(rrset(VICTIM, dns.rdatatype.A, VICTIM_A), PARENT_KEY)


class AacAHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [AAC]
    qtypes = [dns.rdatatype.A]
    answer = signed(rrset(AAC, dns.rdatatype.A, AAC_A), PARENT_KEY)


class MaliciousReferralHandler(DomainHandler, StaticResponseHandler):
    """
    Serve the poisoned referral for the child zone and its subdomains: the
    parent-signed delegation NSEC, plus two piggy-backed NSEC RRs (a fake empty
    non-terminal and a fake range) carrying garbage RRSIGs.  The child's DS
    query is answered by ChildDsHandler, installed before this handler.
    """

    domains = [CHILD]
    authority = (
        [rrset(CHILD, dns.rdatatype.NS, CHILD_NS)]
        + signed(nsec_deleg_child(), PARENT_KEY)
        + garbage_signed(stuffed_ent_nsec(), PARENT_KEY)
        + garbage_signed(stuffed_range_nsec(), PARENT_KEY)
    )
    additional = [rrset(CHILD_NS, dns.rdatatype.A, CHILD_NS_A)]


class ApexNodataHandler(QnameHandler, StaticResponseHandler):
    qnames = [PARENT]
    authority = signed(soa(PARENT), PARENT_KEY) + signed(nsec_apex(), PARENT_KEY)


class FallbackNxdomainHandler(DomainHandler, StaticResponseHandler):
    domains = [PARENT]
    rcode = dns.rcode.NXDOMAIN
    authority = signed(soa(PARENT), PARENT_KEY) + signed(nsec_apex(), PARENT_KEY)


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        ParentDnskeyHandler(),
        ParentSoaHandler(),
        PrimeNxdomainHandler(),
        ChildDsHandler(),
        VictimAHandler(),
        AacAHandler(),
        MaliciousReferralHandler(),
        ApexNodataHandler(),
        FallbackNxdomainHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
