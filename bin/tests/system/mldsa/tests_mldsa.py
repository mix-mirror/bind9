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

import os
import shutil
from pathlib import Path

import dns.flags
import dns.resolver
import isctest


pytestmark = [
    pytest.mark.extra_artifacts(
        [
            "ns*/*.signed",
            "ns*/K*",
            "ns*/dsset-*",
            "ns*/trusted.conf",
            "ns1/root.db",
            "ns*/named.run",
            "ns*/named.run.prev",
            "ns*/named.log",
            "*.log.txt",
        ]
    ),
    pytest.mark.algorithm_set("rsa_only"),
]


def _run(cmd, cwd):
    return isctest.run.cmd(cmd, cwd=cwd, log_stdout=False, log_stderr=True)


def _write_trust_anchor(ds_text, path):
    # Convert "<name> IN DS <keyid> <alg> <digesttype> <digest>" to static-ds.
    line = ds_text.strip().splitlines()[0].split()
    name = line[0]
    key_id, alg, digest_type = line[3:6]
    digest = "".join(line[6:])
    config = (
        "trust-anchors {\n"
        f"    \"{name}\" static-ds {key_id} {alg} {digest_type} \"{digest}\";\n"
        "};\n"
    )
    path.write_text(config, encoding="ascii")


def bootstrap():
    if os.environ.get("MLDSA44_SUPPORTED") != "1":
        pytest.skip("ML-DSA-44 not supported")

    keygen = os.environ["KEYGEN"]
    signer = os.environ["SIGNER"]
    verify = os.environ["VERIFY"]
    dsfromkey = os.environ["DSFROMKEY"]

    ns1 = Path("ns1")
    ns2 = Path("ns2")

    zone = "."

    # Prepare zone file
    shutil.copyfile(ns1 / "root.db.in", ns1 / "root.db")

    # Generate KSK and ZSK
    ksk = _run([keygen, "-a", "ML-DSA-44", "-f", "KSK", zone], cwd=ns1).out.strip()
    zsk = _run([keygen, "-a", "ML-DSA-44", zone], cwd=ns1).out.strip()

    # Add DNSKEYs to zone
    with open(ns1 / "root.db", "a", encoding="ascii") as f:
        f.write((ns1 / f"{ksk}.key").read_text(encoding="ascii"))
        f.write((ns1 / f"{zsk}.key").read_text(encoding="ascii"))

    # Sign the zone
    _run([signer, "-P", "-g", "-o", zone, "root.db"], cwd=ns1)
    signer_err = ns1 / "signer.err"
    if signer_err.exists():
        # Signer writes progress to stderr; remove leftover file to avoid artifact check.
        signer_err.unlink()

    # Verify signatures
    _run([verify, "-o", zone, "root.db.signed"], cwd=ns1)

    # Build trust anchor for resolver
    ds_out = _run([dsfromkey, "-a", "sha-256", f"{ksk}.key"], cwd=ns1).out
    _write_trust_anchor(ds_out, ns1 / "trusted.conf")
    shutil.copyfile(ns1 / "trusted.conf", ns2 / "trusted.conf")


def test_mldsa_authoritative_and_resolver(ns1, ns2, named_port):
    bootstrap()

    # Query authoritative server to ensure zone loads
    auth = dns.resolver.Resolver(configure=False)
    auth.nameservers = ["10.53.0.1"]
    auth.port = int(named_port)
    auth.use_edns(0, dns.flags.DO)
    auth.timeout = 5
    auth.lifetime = 5
    answer = auth.resolve(".", "SOA", tcp=True)
    assert answer.response.rcode() == 0

    # Resolver validation path
    res = dns.resolver.Resolver(configure=False)
    res.nameservers = ["10.53.0.2"]
    res.port = int(named_port)
    res.use_edns(0, dns.flags.DO)
    res.timeout = 5
    res.lifetime = 5
    validated = res.resolve(".", "SOA", tcp=True)
    assert validated.response.rcode() == 0
    assert validated.response.flags & dns.flags.AD
