#!/usr/bin/python3

# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# SPDX-License-Identifier: MPL-2.0

from pathlib import Path

import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import dns.dnssec
import dns.name
import dns.rdataclass
import dns.rdatatype
import pytest

import isctest
import isctest.mark

PARENT = "p031.test."
CHILD = f"c.{PARENT}"
GRANDCHILD = f"grand.{CHILD}"
ATTACK = f"www-bind.{GRANDCHILD}"
FORGED_A = "6.6.6.60"
AUTH = "10.53.0.1"
RESOLVER = "10.53.0.2"

pytestmark = [
    isctest.mark.with_ecdsa_deterministic,
    pytest.mark.extra_artifacts(
        [
            "ans*/ans.run",
            "ans*/keys.json",
        ]
    ),
]


def _make_key():
    private_key = ec.generate_private_key(ec.SECP256R1())
    dnskey = dns.dnssec.make_dnskey(
        private_key.public_key(),
        algorithm="ECDSAP256SHA256",
        flags=257,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    return {
        "private_pem": private_pem,
        "dnskey": dnskey.to_text(),
    }


def bootstrap():
    keys = {PARENT: _make_key()}
    Path("ans1/keys.json").write_text(json.dumps(keys, indent=2), encoding="ascii")
    parent_dnskey = "".join(keys[PARENT]["dnskey"].split()[3:])
    return {"PARENT_DNSKEY": parent_dnskey}


def _query(server, qname, qtype):
    query = isctest.query.create(qname, qtype)
    return isctest.query.tcp(query, server)


def _rrset(response, section, owner, rdtype, covers=None):
    if covers is None:
        return response.get_rrset(
            section,
            dns.name.from_text(owner),
            dns.rdataclass.IN,
            rdtype,
        )
    return response.get_rrset(
        section,
        dns.name.from_text(owner),
        dns.rdataclass.IN,
        rdtype,
        covers=covers,
    )


def _has_a(response, section, owner, address):
    rrset = _rrset(response, section, owner, dns.rdatatype.A)
    return rrset is not None and any(rdata.address == address for rdata in rrset)


def _check_signed_rrset(response, section, owner, rdtype, signer):
    rrsig = _rrset(
        response,
        section,
        owner,
        dns.rdatatype.RRSIG,
        covers=rdtype,
    )
    assert rrsig is not None, response.to_text()
    assert rrsig[0].signer == dns.name.from_text(signer), response.to_text()


def test_forged_grandparent_nsec():
    child_ds = _query(AUTH, CHILD, "DS")
    isctest.check.noerror(child_ds)
    assert _rrset(child_ds, child_ds.answer, CHILD, dns.rdatatype.DS) is not None
    _check_signed_rrset(child_ds, child_ds.answer, CHILD, dns.rdatatype.DS, PARENT)

    grandchild_ds = _query(AUTH, GRANDCHILD, "DS")
    isctest.check.noerror(grandchild_ds)
    nsec = _rrset(
        grandchild_ds, grandchild_ds.authority, GRANDCHILD, dns.rdatatype.NSEC
    )
    assert nsec is not None, grandchild_ds.to_text()
    assert nsec[0].next == dns.name.from_text(
        f"grandz.{CHILD}"
    ), grandchild_ds.to_text()
    _check_signed_rrset(
        grandchild_ds,
        grandchild_ds.authority,
        GRANDCHILD,
        dns.rdatatype.NSEC,
        PARENT,
    )


def test_resolver_rejects_grandparent_nsec_downgrade():
    response = _query(RESOLVER, ATTACK, "A")
    isctest.check.servfail(response)
    isctest.check.noadflag(response)
    assert not _has_a(response, response.answer, ATTACK, FORGED_A), response.to_text()
