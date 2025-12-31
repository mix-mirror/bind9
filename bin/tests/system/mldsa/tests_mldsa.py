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

from pathlib import Path

import base64
import os
import shutil

import dns.flags
import dns.rdata
import dns.rdatatype
import pytest

import isctest

pytestmark = pytest.mark.extra_artifacts(
    ["ns*/*.signed", "ns*/K*", "ns*/dsset-*", "ns*/trusted.conf", "ns1/root.db"]
)


def bootstrap():
    if os.environ.get("MLDSA44_SUPPORTED") != "1":
        pytest.skip("ML-DSA-44 not supported")

    ns1 = Path("ns1")
    shutil.copyfile(ns1 / "root.db.in", ns1 / "root.db")
    keys = []
    for flags in (["-f", "KSK"], []):
        key = isctest.run.cmd(
            [os.environ["KEYGEN"], "-a", "MLDSA44", *flags, "."], cwd=ns1
        ).out.strip()
        keys.append(key)
        private = (ns1 / f"{key}.private").read_text(encoding="ascii")
        seed = next(
            line.split()[1]
            for line in private.splitlines()
            if line.startswith("PrivateKey:")
        )
        assert len(base64.b64decode(seed)) == 32
        with (ns1 / "root.db").open("a", encoding="ascii") as zone:
            zone.write((ns1 / f"{key}.key").read_text(encoding="ascii"))

    isctest.run.cmd(
        [os.environ["SIGNER"], "-n", "1", "-g", "-o", ".", "root.db"], cwd=ns1
    )
    isctest.run.cmd([os.environ["VERIFY"], "-o", ".", "root.db.signed"], cwd=ns1)
    ds = isctest.run.cmd(
        [os.environ["DSFROMKEY"], "-a", "sha-256", f"{keys[0]}.key"], cwd=ns1
    ).out.split()
    assert ds[4] == "18"
    trust = f'trust-anchors {{ "." static-ds {ds[3]} 18 2 "{"".join(ds[6:])}"; }};\n'
    (ns1 / "trusted.conf").write_text(trust, encoding="ascii")
    Path("ns2/trusted.conf").write_text(trust, encoding="ascii")


def test_mldsa_authoritative_and_resolver():
    query = isctest.query.create(".", "SOA", use_edns=0, dnssec=True)
    authoritative = isctest.query.tcp(query, "10.53.0.1")
    validated = isctest.query.tcp(query, "10.53.0.2")
    isctest.check.noerror(authoritative)
    isctest.check.noerror(validated)
    isctest.check.rrsets_equal(authoritative.answer, validated.answer)
    assert validated.flags & dns.flags.AD
    rrsigs = [
        rrset for rrset in validated.answer if rrset.rdtype == dns.rdatatype.RRSIG
    ]
    assert rrsigs
    for rrset in rrsigs:
        for signature in rrset:
            assert signature.algorithm == 18
            assert len(signature.signature) == 2420


def test_mldsa_udp_truncation():
    query = isctest.query.create(".", "DNSKEY", use_edns=0, dnssec=True, payload=1232)
    response = isctest.query.udp(query, "10.53.0.1")
    assert response.flags & dns.flags.TC
    response = isctest.query.tcp(query, "10.53.0.2")
    isctest.check.noerror(response)
    assert response.flags & dns.flags.AD
    keys = response.find_rrset(response.answer, ".", "IN", "DNSKEY")
    assert len(keys) == 2
    assert all(key.algorithm == 18 and len(key.key) == 1312 for key in keys)


def draft_key():
    return (
        Path(os.environ["TOP_SRCDIR"])
        / "tests/dns/testdata/dst"
        / "Kexample.com.+018+59829"
    )


def test_mldsa_draft_ds():
    ds = isctest.run.cmd(
        [os.environ["DSFROMKEY"], "-a", "sha-256", f"{draft_key()}.key"]
    ).out.split()
    assert ds[:6] == ["example.com.", "IN", "DS", "59829", "18", "2"]
    assert "".join(ds[6:]).lower() == (
        "812cb1a22af04380e2f72d91c06c14eb1a918cf30037a8a9c67497e9264b4bfa"
    )


@pytest.mark.parametrize(
    "seed",
    [None, bytes(31), bytes(33), bytes(32)],
    ids=["missing", "short", "long", "mismatch"],
)
def test_mldsa_bad_private_seed(tmp_path, seed):
    """
    Reject a missing seed, wrong seed lengths, and a seed that doesn't
    match the DNSKEY.
    """
    key = draft_key()
    shutil.copyfile(f"{key}.key", tmp_path / f"{key.name}.key")
    private = "Private-key-format: v1.3\nAlgorithm: 18 (MLDSA44)\n"
    if seed is not None:
        private += f"PrivateKey: {base64.b64encode(seed).decode('ascii')}\n"
    (tmp_path / f"{key.name}.private").write_text(private, encoding="ascii")
    result = isctest.run.cmd(
        [os.environ["SETTIME"], "-p", "all", key.name],
        cwd=tmp_path,
        raise_on_exception=False,
    )
    assert result.rc != 0
    assert "private key is invalid" in result.err


def test_mldsa_policy_keygen(tmp_path):
    config = tmp_path / "policy.conf"
    config.write_text(
        'dnssec-policy "mldsa" { keys { csk lifetime unlimited algorithm MLDSA44; }; };\n',
        encoding="ascii",
    )
    key = isctest.run.cmd(
        [os.environ["KEYGEN"], "-k", "mldsa", "-l", str(config), "policy.example."],
        cwd=tmp_path,
    ).out.strip()
    text = (tmp_path / f"{key}.key").read_text(encoding="ascii")
    record = next(line for line in text.splitlines() if not line.startswith(";"))
    key = dns.rdata.from_text("IN", "DNSKEY", record.split("DNSKEY", 1)[1])
    assert key.algorithm == 18
    assert len(key.key) == 1312
