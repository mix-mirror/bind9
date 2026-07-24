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
    QnameHandler,
    QnameQtypeHandler,
    StaticResponseHandler,
)

TTL = 300
TLD = "tld.test."
APEX_HASH = "1B40241KFORIOG780N4IKSCRLVETPCTQ"
ATTACKER = f"{APEX_HASH.lower()}.{TLD}"
VICTIM = f"victim.{TLD}"
AUTH_IP = "10.53.0.1"
TLD_NS = f"ns.{TLD}"
ATTACKER_NS = f"ns.{ATTACKER}"


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


def dnskey(zone: str) -> dns.rrset.RRset:
    return rrset_from_rdata(zone, KEYS[zone].dnskey)


def ds(zone: str) -> dns.rrset.RRset:
    return rrset_from_rdata(zone, KEYS[zone].ds)


def soa(zone: str) -> dns.rrset.RRset:
    return rrset(
        zone,
        dns.rdatatype.SOA,
        f"ns.{zone} hostmaster.{zone} 1 3600 600 86400 300",
    )


def ns(zone: str, target: str) -> dns.rrset.RRset:
    return rrset(zone, dns.rdatatype.NS, target)


def glue(target: str, address: str) -> dns.rrset.RRset:
    return rrset(target, dns.rdatatype.A, address)


def child_nsec3() -> dns.rrset.RRset:
    rdata = dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.NSEC3,
        f"1 0 0 - {APEX_HASH} NS SOA RRSIG DNSKEY NSEC3PARAM",
    )
    return dns.rrset.from_rdata(f"{APEX_HASH}.{TLD}", TTL, rdata)


class VictimForgedNxdomainHandler(QnameQtypeHandler, StaticResponseHandler):
    """
    Serve the forged response for the victim's domain.  The NSEC3 owner name
    derives the zone tld.test., but the RRSIG signer is the malicious child
    zone 1b40241kforiog780n4ikscrlvetpctq.tld.test.
    """

    qnames = [VICTIM]
    qtypes = [dns.rdatatype.A]
    rcode = dns.rcode.NXDOMAIN
    authority = signed(soa(TLD), KEYS[TLD]) + signed(child_nsec3(), KEYS[ATTACKER])


class AttackerDsHandler(QnameQtypeHandler, StaticResponseHandler):
    """
    Spoof the response for the malicious zone when qtype is DS.  It is
    actually a validly signed DS response.
    """

    qnames = [ATTACKER]
    qtypes = [dns.rdatatype.DS]
    answer = signed(ds(ATTACKER), KEYS[TLD])


class AttackerApexDnskeyHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [ATTACKER]
    qtypes = [dns.rdatatype.DNSKEY]
    answer = signed(dnskey(ATTACKER), KEYS[ATTACKER])


class AttackerApexSoaHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [ATTACKER]
    qtypes = [dns.rdatatype.SOA]
    answer = signed(soa(ATTACKER), KEYS[ATTACKER])


class AttackerApexNsHandler(QnameHandler, StaticResponseHandler):
    qnames = [ATTACKER]
    answer = signed(ns(ATTACKER, ATTACKER_NS), KEYS[ATTACKER])
    additional = [glue(ATTACKER_NS, AUTH_IP)]


class AttackerNxdomainHandler(DomainHandler, StaticResponseHandler):
    """
    Names below the apex are answered with an NXDOMAIN with no NSEC or NSEC3
    present.
    """

    domains = [ATTACKER]
    rcode = dns.rcode.NXDOMAIN
    authority = signed(soa(ATTACKER), KEYS[ATTACKER])


class TldApexDnskeyHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [TLD]
    qtypes = [dns.rdatatype.DNSKEY]
    answer = signed(dnskey(TLD), KEYS[TLD])


class TldApexSoaHandler(QnameQtypeHandler, StaticResponseHandler):
    qnames = [TLD]
    qtypes = [dns.rdatatype.SOA]
    answer = signed(soa(TLD), KEYS[TLD])


class TldApexNsHandler(QnameHandler, StaticResponseHandler):
    qnames = [TLD]
    answer = signed(ns(TLD, TLD_NS), KEYS[TLD])
    additional = [glue(TLD_NS, AUTH_IP)]


class TldNxdomainHandler(DomainHandler, StaticResponseHandler):
    """
    Names below the apex are answered with an NXDOMAIN with no NSEC or NSEC3
    present.  If this were a regular name server the attack would not work;
    it assumes the adversary can inject these responses on-path.
    """

    domains = [TLD]
    rcode = dns.rcode.NXDOMAIN
    authority = signed(soa(TLD), KEYS[TLD])


def main() -> None:
    server = AsyncDnsServer(default_aa=True, default_rcode=dns.rcode.NOERROR)
    server.install_response_handlers(
        VictimForgedNxdomainHandler(),
        AttackerDsHandler(),
        AttackerApexDnskeyHandler(),
        AttackerApexSoaHandler(),
        AttackerApexNsHandler(),
        AttackerNxdomainHandler(),
        TldApexDnskeyHandler(),
        TldApexSoaHandler(),
        TldApexNsHandler(),
        TldNxdomainHandler(),
    )
    server.run()


if __name__ == "__main__":
    main()
